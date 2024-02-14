use packet::{BytePacketBuffer, DNSPacket, Result};
use std::net::{Ipv4Addr, UdpSocket};

use crate::packet::{DNSQuestion, QueryType, ResultCode};

mod packet;

fn recursive_lookup(qname: &str, qtype: QueryType) -> Result<DNSPacket> {
    // a.root-servers.net
    let mut ns: Ipv4Addr = "198.41.0.4".parse().unwrap();

    loop {
        println!("Looking up {:?} {} with ns {}", qtype, qname, ns);

        let ns_copy = ns;
        let server = (ns_copy, 53);
        let response = lookup(qname, qtype, server)?;

        // Answer and no errors -> we're done
        if !response.answers.is_empty() && response.header.rescode == ResultCode::NOERROR {
            return Ok(response);
        }

        // Doesn't exist
        if response.header.rescode == ResultCode::NXDOMAIN {
            return Ok(response);
        }

        // Look somewhere else
        if let Some(new_ns) = response.get_resolved_ns(qname) {
            ns = new_ns;
            continue;
        }

        // Resolve NS record to IP
        let new_ns_name = match response.get_unresolved_ns(qname) {
            Some(name) => name,
            None => return Ok(response),
        };

        let recursive_resp = recursive_lookup(&new_ns_name, QueryType::A)?;

        if let Some(new_ns) = recursive_resp.get_random_a() {
            ns = new_ns;
        } else {
            return Ok(response);
        }
    }
}

fn lookup(qname: &str, qtype: QueryType, server: (Ipv4Addr, u16)) -> Result<DNSPacket> {
    let socket = UdpSocket::bind(("0.0.0.0", 42069))?;

    let mut packet = DNSPacket::new();

    packet.header.id = 1337;
    packet.header.questions = 1;
    packet.header.recursion_desired = true;
    packet
        .questions
        .push(DNSQuestion::new(qname.to_string(), qtype));

    let mut buffer = BytePacketBuffer::new();
    packet.write(&mut buffer)?;

    socket.send_to(&buffer.buf[0..buffer.pos], server)?;

    let mut resp_buffer = BytePacketBuffer::new();
    socket.recv(&mut resp_buffer.buf)?;

    DNSPacket::from_buffer(&mut resp_buffer)
}

fn handle_query(socket: &UdpSocket) -> Result<()> {
    let mut req_buffer = BytePacketBuffer::new();

    let (_, source) = socket.recv_from(&mut req_buffer.buf)?;

    let mut request = DNSPacket::from_buffer(&mut req_buffer)?;

    let mut response = DNSPacket::new();
    response.header.id = request.header.id;
    response.header.recursion_desired = true;
    response.header.recursion_available = true;
    response.header.response = true;

    if let Some(question) = request.questions.pop() {
        println!("Received query: {:?}", question);
        if let Ok(result) = recursive_lookup(&question.name, question.qtype) {
            response.questions.push(question);
            response.header.rescode = result.header.rescode;

            for rec in result.answers {
                println!("Answer: {:?}", rec);
                response.answers.push(rec);
            }
            for rec in result.authorities {
                println!("Authority: {:?}", rec);
                response.authorities.push(rec);
            }
            for rec in result.resources {
                println!("Resource: {:?}", rec);
                response.resources.push(rec);
            }
        } else {
            response.header.rescode = ResultCode::SERVFAIL;
        }
    } else {
        response.header.rescode = ResultCode::FORMERR;
    }

    let mut resp_buffer = BytePacketBuffer::new();
    response.write(&mut resp_buffer)?;
    let len = resp_buffer.pos;
    let data = resp_buffer.peek_many(0, len)?;

    socket.send_to(data, source)?;

    Ok(())
}

fn main() -> Result<()> {
    let socket = UdpSocket::bind(("0.0.0.0", 2053))?;

    loop {
        match handle_query(&socket) {
            Ok(_) => {}
            Err(e) => eprintln!("An error occurred: {}", e),
        }
    }
}
