use clap::{Parser, ValueEnum};
use colored::Colorize;
use crossterm::{
    event::{self, Event, KeyCode, KeyEventKind},
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
    ExecutableCommand,
};
use inquire::MultiSelect;
use ratatui::{
    prelude::*,
    widgets::{Block, Borders, Cell, Clear, Paragraph, Row, Table, TableState},
};
use std::collections::{HashMap, HashSet};
use std::fmt;
use std::io::stdout;
use std::thread;
use std::time::{Duration, Instant};
use sysinfo::System;
use terminal_size::{terminal_size, Width};

#[cfg(unix)]
use nix::sys::signal::Signal;

#[cfg(windows)]
#[derive(Debug, Clone, Copy, ValueEnum, PartialEq)]
pub enum Signal {
    Kill,
    Term,
}

#[derive(Debug, Clone, Copy, ValueEnum, PartialEq)]
enum SortBy {
    Cpu,
    Mem,
    Pid,
    Name,
    Port,
}

#[derive(Parser)]
#[command(name = "rip", version, about = "Fuzzy find and kill processes", disable_version_flag = true)]
struct Args {
    /// Print version
    #[arg(short = 'v', long = "version", action = clap::ArgAction::Version)]
    _version: (),

    /// Pre-filter processes by name
    #[arg(short, long)]
    filter: Option<String>,

    /// Signal to send (default SIGKILL)
    #[arg(short, long, default_value = "KILL")]
    signal: String,

    /// Sort processes by field (default: cpu)
    #[arg(long, value_enum, default_value = "cpu")]
    sort: SortBy,

    /// Live mode with auto-refreshing processes list
    #[arg(short, long)]
    live: bool,

    /// Show only processes with open ports
    #[arg(long)]
    ports: bool,

    /// Filter by specific port number
    #[arg(long, value_name = "PORT")]
    port: Option<u16>,

    /// Nuke all matching processes with pre-confirmation to the filter (-f) or the port (--port)
    #[arg(long = "confirm-nuke")]
    confirm_nuke: bool,
}

fn truncate(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        format!("{}...", &s[..max_len - 3])
    }
}

fn calculate_name_width(ports_mode: bool) -> usize {
    let term_width = terminal_size()
        .map(|(Width(w), _)| w as usize)
        .unwrap_or(80);

    let mut fixed = 6 + 7 + 7 + 9 + 4;

    if ports_mode {
        fixed += 10;
    }

    let available = term_width.saturating_sub(fixed);
    available.clamp(15, 80)
}

#[derive(Clone)]
struct ProcessInfo {
    pid: u32,
    name: String,
    cpu: f32,
    memory: u64,
    name_width: usize,
    port: Option<u16>,
    protocol: Option<String>,
}

impl fmt::Display for ProcessInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let display_name = truncate(&self.name, self.name_width);
        let pid_formatted = format!("{:<7}", self.pid);
        let name_formatted = format!("{:<width$}", display_name, width = self.name_width);
        let cpu_formatted = format!("{:>6.1}%", self.cpu);
        let mem_formatted = format!("{:>9}", format!("{} MB", self.memory));

        let pid_str = Colorize::dimmed(pid_formatted.as_str());
        let name_str = Colorize::white(name_formatted.as_str());
        let cpu_colored = if self.cpu > 50.0 {
            Colorize::bold(Colorize::red(cpu_formatted.as_str()))
        } else if self.cpu > 10.0 {
            Colorize::yellow(cpu_formatted.as_str())
        } else {
            Colorize::dimmed(cpu_formatted.as_str())
        };
        let mem_colored = if self.memory > 500 {
            Colorize::bold(Colorize::red(mem_formatted.as_str()))
        } else if self.memory > 100 {
            Colorize::yellow(mem_formatted.as_str())
        } else {
            Colorize::dimmed(mem_formatted.as_str())
        };

        if let Some(port) = self.port {
            let proto = self.protocol.as_deref().unwrap_or("TCP");
            let port_formatted = format!("{:<5} {:>3}", port, proto);
            let port_str = Colorize::green(port_formatted.as_str());
            write!(
                f,
                "{} {} {} {} {}",
                port_str, pid_str, name_str, cpu_colored, mem_colored
            )
        } else {
            write!(f, "{} {} {} {}", pid_str, name_str, cpu_colored, mem_colored)
        }
    }
}

fn get_processes(filter: Option<&str>, sort_by: SortBy) -> Vec<ProcessInfo> {
    let mut sys = System::new_all();
    sys.refresh_all();
    thread::sleep(Duration::from_millis(200));
    sys.refresh_all();

    let name_width = calculate_name_width(false);

    let mut processes: Vec<ProcessInfo> = sys
        .processes()
        .iter()
        .filter_map(|(pid, proc)| {
            let name = proc.name().to_string_lossy().to_string();

            if let Some(f) = filter {
                if !name.to_lowercase().contains(&f.to_lowercase()) {
                    return None;
                }
            }

            Some(ProcessInfo {
                pid: pid.as_u32(),
                name,
                cpu: proc.cpu_usage(),
                memory: proc.memory() / 1024 / 1024,
                name_width,
                port: None,
                protocol: None,
            })
        })
        .collect();

    sort_processes(&mut processes, sort_by);
    processes
}

fn sort_processes(processes: &mut Vec<ProcessInfo>, sort_by: SortBy) {
    match sort_by {
        SortBy::Cpu => processes.sort_by(|a, b| b.cpu.partial_cmp(&a.cpu).unwrap()),
        SortBy::Mem => processes.sort_by(|a, b| b.memory.cmp(&a.memory)),
        SortBy::Pid => processes.sort_by(|a, b| a.pid.cmp(&b.pid)),
        SortBy::Name => processes.sort_by(|a, b| a.name.to_lowercase().cmp(&b.name.to_lowercase())),
        SortBy::Port => processes.sort_by(|a, b| a.port.cmp(&b.port)),
    }
}

fn get_port_mappings() -> HashMap<u32, Vec<(u16, String)>> {
    let mut map: HashMap<u32, Vec<(u16, String)>> = HashMap::new();

    if let Ok(listeners) = listeners::get_all() {
        for listener in listeners {
            let port = listener.socket.port();
            let protocol = format!("{:?}", listener.protocol).to_uppercase();
            let entry = map.entry(listener.process.pid).or_default();
            if !entry.iter().any(|(p, proto)| *p == port && proto == &protocol) {
                entry.push((port, protocol));
            }
        }
    }

    map
}

fn get_processes_with_ports(
    filter: Option<&str>,
    port_filter: Option<u16>,
    sort_by: SortBy,
) -> Vec<ProcessInfo> {
    let mut sys = System::new_all();
    sys.refresh_all();
    thread::sleep(Duration::from_millis(200));
    sys.refresh_all();

    let port_map = get_port_mappings();
    let name_width = calculate_name_width(true);

    let mut processes: Vec<ProcessInfo> = sys
        .processes()
        .iter()
        .flat_map(|(pid, proc)| {
            let pid_u32 = pid.as_u32();
            let ports = match port_map.get(&pid_u32) {
                Some(p) => p,
                None => return vec![],
            };

            let name = proc.name().to_string_lossy().to_string();

            if let Some(f) = filter {
                if !name.to_lowercase().contains(&f.to_lowercase()) {
                    return vec![];
                }
            }

            let cpu = proc.cpu_usage();
            let memory = proc.memory() / 1024 / 1024;

            ports
                .iter()
                .filter_map(|(port, protocol)| {
                    if let Some(target_port) = port_filter {
                        if *port != target_port {
                            return None;
                        }
                    }

                    Some(ProcessInfo {
                        pid: pid_u32,
                        name: name.clone(),
                        cpu,
                        memory,
                        name_width,
                        port: Some(*port),
                        protocol: Some(protocol.clone()),
                    })
                })
                .collect::<Vec<_>>()
        })
        .collect();

    sort_processes(&mut processes, sort_by);
    processes
}

fn parse_signal(signal_str: &str) -> Result<Signal, String> {
    let signal_str = signal_str.to_uppercase();
    let signal_str = signal_str.strip_prefix("SIG").unwrap_or(&signal_str);

    #[cfg(unix)]
    {
        match signal_str {
            "KILL" | "9" => Ok(Signal::SIGKILL),
            "TERM" | "15" => Ok(Signal::SIGTERM),
            "INT" | "2" => Ok(Signal::SIGINT),
            "HUP" | "1" => Ok(Signal::SIGHUP),
            "QUIT" | "3" => Ok(Signal::SIGQUIT),
            "USR1" | "10" => Ok(Signal::SIGUSR1),
            "USR2" | "12" => Ok(Signal::SIGUSR2),
            "STOP" | "19" => Ok(Signal::SIGSTOP),
            "CONT" | "18" => Ok(Signal::SIGCONT),
            _ => Err(format!("Unknown signal: {}", signal_str)),
        }
    }

    #[cfg(windows)]
    {
        match signal_str {
            "KILL" | "9" => Ok(Signal::Kill),
            "TERM" | "15" => Ok(Signal::Term),
            _ => Err(format!("Only KILL and TERM are supported on Windows: {}", signal_str)),
        }
    }
}

fn run_selector(processes: Vec<ProcessInfo>, ports_mode: bool) -> Vec<ProcessInfo> {
    if processes.is_empty() {
        return vec![];
    }

    let name_width = calculate_name_width(ports_mode);
    let pid_h = format!("{:<7}", "PID");
    let name_h = format!("{:<width$}", "NAME", width = name_width);
    let cpu_h = format!("{:>7}", "CPU %");
    let mem_h = format!("{:>9}", "MEMORY");

    let header = if ports_mode {
        let port_h = format!("{:<9}", "PORT");
        format!(
            "    {} {} {} {} {}",
            Colorize::dimmed(port_h.as_str()),
            Colorize::dimmed(pid_h.as_str()),
            Colorize::dimmed(name_h.as_str()),
            Colorize::dimmed(cpu_h.as_str()),
            Colorize::dimmed(mem_h.as_str()),
        )
    } else {
        format!(
            "    {} {} {} {}",
            Colorize::dimmed(pid_h.as_str()),
            Colorize::dimmed(name_h.as_str()),
            Colorize::dimmed(cpu_h.as_str()),
            Colorize::dimmed(mem_h.as_str()),
        )
    };

    let ans = MultiSelect::new(&format!("{}\n", header), processes)
        .with_page_size(15)
        .with_help_message("↑↓ navigate • Space select • Enter confirm • Type to filter")
        .prompt();

    match ans {
        Ok(selected) => selected,
        Err(_) => vec![],
    }
}

fn run_live_mode(
    filter: Option<&str>,
    sort_by: SortBy,
    signal: Signal,
    ports_mode: bool,
    port_filter: Option<u16>,
) -> std::io::Result<()> {
    enable_raw_mode()?;
    stdout().execute(EnterAlternateScreen)?;
    let mut terminal = Terminal::new(CrosstermBackend::new(stdout()))?;

    let mut table_state = TableState::default();
    table_state.select(Some(0));
    let mut selected_pids: HashSet<u32> = HashSet::new();
    let mut last_refresh = Instant::now();
    let refresh_interval = Duration::from_secs(2);
    let mut sys = System::new_all();
    let mut processes = if ports_mode {
        refresh_processes_with_ports(&mut sys, filter, port_filter, sort_by)
    } else {
        refresh_processes(&mut sys, filter, sort_by)
    };
    let mut show_confirm = false;

    loop {
        if last_refresh.elapsed() >= refresh_interval && !show_confirm {
            processes = if ports_mode {
                refresh_processes_with_ports(&mut sys, filter, port_filter, sort_by)
            } else {
                refresh_processes(&mut sys, filter, sort_by)
            };
            last_refresh = Instant::now();
            if let Some(selected) = table_state.selected() {
                if selected >= processes.len() && !processes.is_empty() {
                    table_state.select(Some(processes.len() - 1));
                }
            }
        }

        terminal.draw(|frame| {
            let area = frame.area();
            let rows: Vec<Row> = processes
                .iter()
                .map(|p| {
                    let is_selected = selected_pids.contains(&p.pid);
                    let marker = if is_selected { "●" } else { " " };
                    let cpu_style = if p.cpu > 50.0 {
                        Style::default().fg(Color::Red).bold()
                    } else if p.cpu > 10.0 {
                        Style::default().fg(Color::Yellow)
                    } else {
                        Style::default().fg(Color::DarkGray)
                    };

                    let mut cells = vec![
                        Cell::from(marker).style(if is_selected {
                            Style::default().fg(Color::Green).bold()
                        } else {
                            Style::default()
                        }),
                    ];

                    if ports_mode {
                        let port_str = p
                            .port
                            .map(|port| format!("{:<5}", port))
                            .unwrap_or_default();
                        let proto_str = p.protocol.as_deref().unwrap_or("");
                        cells.push(
                            Cell::from(format!("{} {:>3}", port_str, proto_str))
                                .style(Style::default().fg(Color::Green)),
                        );
                    }

                    cells.extend([
                        Cell::from(format!("{:<7}", p.pid))
                            .style(Style::default().fg(Color::DarkGray)),
                        Cell::from(truncate(&p.name, 40)).style(Style::default().fg(Color::White)),
                        Cell::from(format!("{:>6.1}%", p.cpu)).style(cpu_style),
                        Cell::from(format!("{:>6} MB", p.memory))
                            .style(Style::default().fg(Color::Cyan)),
                    ]);

                    Row::new(cells)
                })
                .collect();

            let (header, widths): (Row, Vec<Constraint>) = if ports_mode {
                (
                    Row::new(vec![
                        Cell::from(" "),
                        Cell::from(format!("{:<9}", "PORT"))
                            .style(Style::default().fg(Color::DarkGray)),
                        Cell::from(format!("{:<7}", "PID"))
                            .style(Style::default().fg(Color::DarkGray)),
                        Cell::from("NAME").style(Style::default().fg(Color::DarkGray)),
                        Cell::from(format!("{:>7}", "CPU %"))
                            .style(Style::default().fg(Color::DarkGray)),
                        Cell::from(format!("{:>9}", "MEMORY"))
                            .style(Style::default().fg(Color::DarkGray)),
                    ])
                    .style(Style::default().bold()),
                    vec![
                        Constraint::Length(2),
                        Constraint::Length(9),
                        Constraint::Length(7),
                        Constraint::Min(20),
                        Constraint::Length(7),
                        Constraint::Length(9),
                    ],
                )
            } else {
                (
                    Row::new(vec![
                        Cell::from(" "),
                        Cell::from(format!("{:<7}", "PID"))
                            .style(Style::default().fg(Color::DarkGray)),
                        Cell::from("NAME").style(Style::default().fg(Color::DarkGray)),
                        Cell::from(format!("{:>7}", "CPU %"))
                            .style(Style::default().fg(Color::DarkGray)),
                        Cell::from(format!("{:>9}", "MEMORY"))
                            .style(Style::default().fg(Color::DarkGray)),
                    ])
                    .style(Style::default().bold()),
                    vec![
                        Constraint::Length(2),
                        Constraint::Length(7),
                        Constraint::Min(20),
                        Constraint::Length(7),
                        Constraint::Length(9),
                    ],
                )
            };

            let selected_count = selected_pids.len();
            let title = if selected_count > 0 {
                format!(" rip - {} selected ", selected_count)
            } else {
                " rip ".to_string()
            };

            let table = Table::new(rows, widths)
                .header(header)
                .block(
                    Block::default()
                        .borders(Borders::ALL)
                        .title(title)
                        .title_bottom(" ↑↓ navigate • Space select • Enter kill • q quit "),
                )
                .row_highlight_style(Style::default().bg(Color::DarkGray).fg(Color::White))
                .highlight_symbol("▶ ");

            frame.render_stateful_widget(table, area, &mut table_state);

            if show_confirm {
                let popup_area = centered_rect(50, 20, area);
                frame.render_widget(Clear, popup_area);

                let count = selected_pids.len();
                let text = format!(
                    "Kill {} process{}?\n\n[Enter] Confirm  [Esc] Cancel",
                    count,
                    if count == 1 { "" } else { "es" }
                );
                let popup = Paragraph::new(text)
                    .alignment(Alignment::Center)
                    .block(
                        Block::default()
                            .borders(Borders::ALL)
                            .title(" Confirm ")
                            .border_style(Style::default().fg(Color::Yellow)),
                    );
                frame.render_widget(popup, popup_area);
            }
        })?;

        if event::poll(Duration::from_millis(100))? {
            if let Event::Key(key) = event::read()? {
                if key.kind == KeyEventKind::Press {
                    if show_confirm {
                        match key.code {
                            KeyCode::Enter => {
                                break;
                            }
                            KeyCode::Esc => {
                                show_confirm = false;
                            }
                            _ => {}
                        }
                    } else {
                        match key.code {
                            KeyCode::Char('q') | KeyCode::Esc => {
                                selected_pids.clear();
                                break;
                            }
                            KeyCode::Up | KeyCode::Char('k') => {
                                if let Some(selected) = table_state.selected() {
                                    if selected > 0 {
                                        table_state.select(Some(selected - 1));
                                    }
                                }
                            }
                            KeyCode::Down | KeyCode::Char('j') => {
                                if let Some(selected) = table_state.selected() {
                                    if selected < processes.len().saturating_sub(1) {
                                        table_state.select(Some(selected + 1));
                                    }
                                }
                            }
                            KeyCode::Char(' ') => {
                                if let Some(selected) = table_state.selected() {
                                    if let Some(proc) = processes.get(selected) {
                                        if selected_pids.contains(&proc.pid) {
                                            selected_pids.remove(&proc.pid);
                                        } else {
                                            selected_pids.insert(proc.pid);
                                        }
                                    }
                                }
                            }
                            KeyCode::Enter => {
                                if !selected_pids.is_empty() {
                                    show_confirm = true;
                                }
                            }
                            _ => {}
                        }
                    }
                }
            }
        }
    }

    disable_raw_mode()?;
    stdout().execute(LeaveAlternateScreen)?;

    if !selected_pids.is_empty() {
        let to_kill: Vec<ProcessInfo> = processes
            .into_iter()
            .filter(|p| selected_pids.contains(&p.pid))
            .collect();
        kill_processes(to_kill, signal);
    }

    Ok(())
}

fn refresh_processes(sys: &mut System, filter: Option<&str>, sort_by: SortBy) -> Vec<ProcessInfo> {
    sys.refresh_all();
    thread::sleep(Duration::from_millis(200));
    sys.refresh_all();

    let name_width = calculate_name_width(false);

    let mut processes: Vec<ProcessInfo> = sys
        .processes()
        .iter()
        .filter_map(|(pid, proc)| {
            let name = proc.name().to_string_lossy().to_string();

            if let Some(f) = filter {
                if !name.to_lowercase().contains(&f.to_lowercase()) {
                    return None;
                }
            }

            Some(ProcessInfo {
                pid: pid.as_u32(),
                name,
                cpu: proc.cpu_usage(),
                memory: proc.memory() / 1024 / 1024,
                name_width,
                port: None,
                protocol: None,
            })
        })
        .collect();

    sort_processes(&mut processes, sort_by);
    processes
}

fn refresh_processes_with_ports(
    sys: &mut System,
    filter: Option<&str>,
    port_filter: Option<u16>,
    sort_by: SortBy,
) -> Vec<ProcessInfo> {
    sys.refresh_all();
    thread::sleep(Duration::from_millis(200));
    sys.refresh_all();

    let port_map = get_port_mappings();
    let name_width = calculate_name_width(true);

    let mut processes: Vec<ProcessInfo> = sys
        .processes()
        .iter()
        .flat_map(|(pid, proc)| {
            let pid_u32 = pid.as_u32();
            let ports = match port_map.get(&pid_u32) {
                Some(p) => p,
                None => return vec![],
            };

            let name = proc.name().to_string_lossy().to_string();

            if let Some(f) = filter {
                if !name.to_lowercase().contains(&f.to_lowercase()) {
                    return vec![];
                }
            }

            let cpu = proc.cpu_usage();
            let memory = proc.memory() / 1024 / 1024;

            ports
                .iter()
                .filter_map(|(port, protocol)| {
                    if let Some(target_port) = port_filter {
                        if *port != target_port {
                            return None;
                        }
                    }

                    Some(ProcessInfo {
                        pid: pid_u32,
                        name: name.clone(),
                        cpu,
                        memory,
                        name_width,
                        port: Some(*port),
                        protocol: Some(protocol.clone()),
                    })
                })
                .collect::<Vec<_>>()
        })
        .collect();

    sort_processes(&mut processes, sort_by);
    processes
}

fn centered_rect(percent_x: u16, percent_y: u16, r: Rect) -> Rect {
    let popup_layout = Layout::vertical([
        Constraint::Percentage((100 - percent_y) / 2),
        Constraint::Percentage(percent_y),
        Constraint::Percentage((100 - percent_y) / 2),
    ])
    .split(r);

    Layout::horizontal([
        Constraint::Percentage((100 - percent_x) / 2),
        Constraint::Percentage(percent_x),
        Constraint::Percentage((100 - percent_x) / 2),
    ])
    .split(popup_layout[1])[1]
}

fn kill_processes(selected: Vec<ProcessInfo>, _signal: Signal) {
    let s = System::new_all();

    for proc in selected {
        let mut killed = false;

        #[cfg(unix)]
        {
            use nix::unistd::Pid as NixPid;
            use nix::sys::signal::kill as nix_kill;
            if nix_kill(NixPid::from_raw(proc.pid as i32), signal).is_ok() {
                killed = true;
            }
        }

        #[cfg(windows)]
        {
            if let Some(process) = s.process(sysinfo::Pid::from_u32(proc.pid)) {
                killed = process.kill();
            }
        }

        if killed {
            println!(
                "{} {} {}",
                Colorize::green("Killed"),
                Colorize::bold(proc.name.as_str()),
                Colorize::dimmed(format!("(PID: {})", proc.pid).as_str())
            );
        } else {
            eprintln!(
                "{} {} {}",
                Colorize::red("Failed"),
                Colorize::bold(proc.name.as_str()),
                Colorize::dimmed(format!("(PID: {})", proc.pid).as_str())
            );
        }
    }
}

fn validate_args(args: &Args) -> Result<(), String> {
    if args.confirm_nuke && args.filter.is_none() && args.port.is_none() {
        return Err("Error: Process --confirm-nuke requires a filter (-f, --filter) or a port (--port) to prevent accidental mass deletion.".to_string());
    }
    Ok(())
}

fn main() {
    let args = Args::parse();

    if let Err(e) = validate_args(&args) {
        eprintln!("{}", Colorize::red(e.as_str()));
        std::process::exit(1);
    }

    let signal = match parse_signal(&args.signal) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
    };

    let ports_mode = args.ports || args.port.is_some();
    let port_filter = args.port;

    if args.live {
        if let Err(e) = run_live_mode(
            args.filter.as_deref(),
            args.sort,
            signal,
            ports_mode,
            port_filter,
        ) {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
        return;
    }

    let processes = if ports_mode {
        get_processes_with_ports(args.filter.as_deref(), port_filter, args.sort)
    } else {
        get_processes(args.filter.as_deref(), args.sort)
    };

    if processes.is_empty() {
        if ports_mode {
            println!("No processes with listening ports found");
        } else {
            println!("No processes found");
        }
        return;
    }

    let selected = if args.confirm_nuke {
        processes
    } else {
        run_selector(processes, ports_mode)
    };

    if selected.is_empty() {
        println!("No processes selected");
        return;
    }

    kill_processes(selected, signal);
}
