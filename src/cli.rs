use clap::Parser;

#[derive(Parser)]
#[command(version, about="A Packet Sniffer", long_about=None)]
pub struct Args {
    #[arg(short, long, default_value_t=false)]
    pub show_payload: bool,

    #[arg(short, long)]
    pub pid: Option<u32>,

    #[arg(short, long)]
    pub count: Option<u32>,
}

