use pcap::Capture;

fn main() {
    println!("Capturing");
    let mut cap = Capture::from_device("wlp0s20f3").unwrap()
        .promisc(true)
        .snaplen(65535)
        .open()
        .unwrap();

    println!("Link type: {}", cap.get_datalink().get_name().unwrap_or("Unknown".to_string()));

    while let Ok(packet) = cap.next_packet() {
        let data = packet.data;
        for chunk in data.chunks(16) {
            let hex: Vec<String> = chunk.iter()
                .map(|b| format!("{:02x}", b)).collect();
            println!("{}", hex.join(" "));
        }
    }
}
