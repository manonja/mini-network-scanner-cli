use std::env;

// TODO: Implement a function that prints out the help message on the screen.
fn help(program_name: &str) {
    let help_message = format!("
************************************************************************************************

    Mini Network Scanner is a small CLI that can scan ports and retrieve basic system information 💜 

    So you can use it to scan your own network... 

    or the network of others.


    Usage: 
    {program_name} --help
    {program_name} -h

    {program_name} --scan <ip_address>
    {program_name} -s <ip_address>

************************************************************************************************
", );
    println!("{}", help_message);
}

fn main() {
    // Collecting the command line arguments into a vector and printing them
    let args: Vec<String> = env::args().collect();

    // TODO: Implement the argv "scanner". It will run through the command line argument
    // and map the arguments to the functions. Note that arguments can have a long and short form.
    // Also note, that in case you have more or unknown arguments, you should let the user know that
    // invalid arguments were provided. Finally, you should return the correct exit code.

    if args.len() > 1 && (args[1] == "--help" || args[1] == "-h") {
        help(&args[0]);
        // exit with success code
        std::process::exit(0);
    }

    // Handle error
    if args.len() < 2 && (args[1] == "--scan" || args[1] == "-s") {
        println!("Please provide an IP address to scan");
        // exit with error code
        std::process::exit(1);
    }
}
