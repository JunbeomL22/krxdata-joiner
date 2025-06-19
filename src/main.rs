use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use anyhow::Context;
use std::fs;
use serde::{Deserialize, Serialize};


#[derive(Serialize, Deserialize, Debug)]
struct MulticastGroup {
    ip: String,
    ports: Vec<u16>,
}

#[derive(Serialize, Deserialize, Debug)]
struct Config {
    local_interface: Ipv4Addr,
    groups: Vec<MulticastGroup>,
}

fn join_multicast_v4() -> std::io::Result<()> {
    let config_str = fs::read_to_string("multicast_group.json")?;
    let config: Config = serde_json::from_str(&config_str).expect("Failed to parse JSON");
    let interface = config.local_interface;
    
    let mut sockets = Vec::new();
    let mut join_count = 0;
    let mut fail_count = 0;

    println!("Starting multicast group joins...");
    
    // Process each group
    for group in &config.groups {
        let ip: Ipv4Addr = group.ip.parse()
            .unwrap_or_else(|_| panic!("Invalid IP address: {}", group.ip));
        
        // Process each port
        for &port in &group.ports {
            match UdpSocket::bind(SocketAddr::new(
                IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                port,
            )) {
                Ok(socket) => {
                    // Set SO_REUSEADDR on the socket
                    #[cfg(unix)]
                    {
                        use std::os::unix::io::AsRawFd;
                        unsafe {
                            let optval: libc::c_int = 1;
                            libc::setsockopt(
                                socket.as_raw_fd(),
                                libc::SOL_SOCKET,
                                libc::SO_REUSEADDR,
                                &optval as *const _ as *const libc::c_void,
                                std::mem::size_of_val(&optval) as libc::socklen_t,
                            );
                        }
                    }

                    #[cfg(windows)]
                    {
                        use std::os::windows::io::AsRawSocket;
                        use winapi::um::winsock2::{setsockopt, SOCKET, SOL_SOCKET, SO_REUSEADDR};
                        unsafe {
                            let optval: i32 = 1;
                            setsockopt(
                                socket.as_raw_socket() as SOCKET,
                                SOL_SOCKET,
                                SO_REUSEADDR,
                                &optval as *const _ as *const i8,
                                std::mem::size_of_val(&optval) as i32,
                            );
                        }
                    }

                    match socket.join_multicast_v4(&ip, &interface) {
                        Ok(_) => {
                            println!("Successfully joined group: {}:{}", ip, port);
                            join_count += 1;
                            sockets.push(socket);
                        }
                        Err(e) => {
                            eprintln!("{}:{} - Failed to join multicast group: {}", ip, port, e);
                            fail_count += 1;
                        }
                    }
                }
                Err(e) => {
                    eprintln!("{}:{} - Failed to create socket: {}", ip, port, e);
                    fail_count += 1;
                }
            }
        }
    }

    println!("\nJoin statistics:");
    println!("  Success: {}", join_count);
    println!("  Failed: {}", fail_count);

    loop {
        std::thread::sleep(std::time::Duration::from_secs(3600 * 24 * 365));
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct TsharkConfig {
    interface: String,
    max_packets: u32,
    duration_seconds: u32,
    output_path: String,
    buffer_size: u32,
    snaplen: u32,
}

impl TsharkConfig {
    fn from_file(path: &str) -> anyhow::Result<Self> {
        let content = fs::read_to_string(path)
            .context("Failed to read config file")?;
        let config: TsharkConfig = serde_json::from_str(&content)
            .context("Failed to parse config file")?;
        Ok(config)
    }
}

impl std::fmt::Display for TsharkConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "Tsark Config:")?;
        writeln!(f, "  Interface: {}", self.interface)?;
        writeln!(f, "  Max Packets: {}", self.max_packets)?;
        writeln!(f, "  Duration: {} seconds", self.duration_seconds)?;
        writeln!(f, "  Output Path: {}", self.output_path)?;
        writeln!(f, "  Buffer Size: {}", self.buffer_size)?;
        writeln!(f, "  Snaplen: {}", self.snaplen)?;

        Ok(())
    }
}

fn run_tshark(config: &TsharkConfig) -> anyhow::Result<()> {
    println!();
    println!("Starting TShark capture...");
    println!();
    println!("Config: {}", config);
    
    let status = std::process::Command::new("tshark")
        .arg("-i").arg(&config.interface)
        .arg("-f").arg("multicast and udp")
        .arg("-b").arg(format!("packets:{}", config.max_packets))
        .arg("-b").arg(format!("duration:{}", config.duration_seconds))
        .arg("-w").arg(&config.output_path)
        .arg("-t").arg("ad")
        .arg("-B").arg(config.buffer_size.to_string())
        .arg("-s").arg(config.snaplen.to_string())
        .arg("-F").arg("pcap")
        .status()
        .context("Failed to execute tshark")?;

    if !status.success() {
        anyhow::bail!("TShark process failed with status: {}", status);
    }

    Ok(())
}

fn main() -> anyhow::Result<()> {
    std::thread::spawn(|| {
        join_multicast_v4().expect("Failed to join multicast groups");
    });
    
    std::thread::sleep(std::time::Duration::from_secs(2));

    let config = TsharkConfig::from_file("tshark_config.json")
        .context("Failed to load TShark config")?;

    run_tshark(&config)?;

    Ok(())
}