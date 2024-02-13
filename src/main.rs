use packet::{BytePacketBuffer, DNSPacket, Result};
use std::net::UdpSocket;

use crate::packet::{DNSQuestion, QueryType};

mod packet;

fn main() -> Result<()> {
    let name = "www.mariotodorov.com";
    let qtype = QueryType::A;

    // Google public DNS
    let server = ("8.8.8.8", 53);

    let socket = UdpSocket::bind(("0.0.0.0", 42069))?;

    let mut packet = DNSPacket::new();

    packet.header.id = 1337;
    packet.header.questions = 1;
    packet.header.recursion_desired = true;
    packet
        .questions
        .push(DNSQuestion::new(name.to_string(), qtype));

    let mut buffer = BytePacketBuffer::new();
    packet.write(&mut buffer)?;

    socket.send_to(&buffer.buf[0..buffer.pos], server)?;

    let mut resp_buffer = BytePacketBuffer::new();
    socket.recv(&mut resp_buffer.buf)?;

    let resp_packet = DNSPacket::from_buffer(&mut resp_buffer)?;
    println!("{:#?}", resp_packet.header);

    for q in resp_packet.questions {
        println!("{:#?}", q);
    }
    for rec in resp_packet.answers {
        println!("{:#?}", rec);
    }
    for rec in resp_packet.authorities {
        println!("{:#?}", rec);
    }
    for rec in resp_packet.resources {
        println!("{:#?}", rec);
    }

    Ok(())
}
