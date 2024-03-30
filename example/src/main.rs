use std::io;

use bson::doc;

fn main() -> io::Result<()> {
    let mut bin = Vec::new();

    let d = doc! {
        "d": 1,
        "r": 2
    };

    match d.to_writer(&mut bin){
        Ok(_) => {}
        Err(e) => return Err(io::Error::new(io::ErrorKind::InvalidData, format!("{e}")))
    }

    println!("Length: {}", bin.len());

    if bin.len() > 4{
        for i in 0..4{
            println!("{i}: {}", bin[i]);
        }
    }

    Ok(())
}
