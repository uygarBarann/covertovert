
# Covert Storage Channel that exploits Protocol Field Manipulation using DNS TTL Field [Code: CSC-PSV-DNS-ATTLF]

## Contributors
- Egemen Gümüşkaya - 2521623
- Uygar Baran Ülgen - 2522092

## Note
[Github repository link](https://github.com/uygarBarann/covertovert)

## Overview
A covert storage channel is a method of secretly transmitting information by utilizing unused or unconventional protocol fields, making the communication challenging to detect. This project utilizes the DNS TTL (Time-To-Live) field for encoding and transmitting covert messages.

- TTL modulo encoding maps binary chunks into TTL values.
- Each DNS packet carries encoded data in its TTL field.

## Implementation Details

### MyCovertChannel

The implementation extends the `CovertChannelBase` class and includes two key functions:

#### send()
- Generates a random binary message ending with a “.” character as a stopping signal.
- Encodes binary chunks of `bits_per_packet` (default: 2 bits) into TTL values using modulo constraints.
- Sends DNS packets to the receiver with encoded TTL values.
- Logs the generated message and transmission details to the file specified in `config.json`.

#### receive()
- Captures incoming DNS packets using `scapy.sniff()`.
- Decodes the TTL field values back into binary chunks based on modulo constraints.
- Reconstructs the original message.
- Stops when the “.” character (stopping signal) is detected.
- Logs the decoded message to the file specified in `config.json`.

## Detailed Function Descriptions

### generate_ttl_with_modulo
This function calculates a TTL value that satisfies a specific modulo condition, ensuring the value remains within the specified range. The process is as follows:

1. Generate a random TTL value within `[min_TTL, max_TTL]`.
2. Adjust the value to satisfy the condition `TTL % modulo_base == modulo_value`.
3. Ensure the adjusted value stays within the valid range by wrapping around using `modulo_base`.

#### Formula:
- If the adjusted TTL is out of bounds:
  - Add `modulo_base` if `TTL < min_TTL`.
  - Subtract `modulo_base` if `TTL > max_TTL`.

### Encoding Logic in send()
1. Divide the binary message into chunks of `bits_per_packet`.
2. Convert each chunk to a modulo value.
3. Generate a random TTL value, whose modulo is equal to modulo value, for each chunk using `generate_ttl_with_modulo`.
4. Send a DNS packet with the TTL value encoded in the header.

### Decoding Logic in receive()
1. Capture incoming DNS packets and extract TTL values.
2. Decode the modulo value from each TTL.
3. Convert the modulo values back to binary chunks.
4. Reconstruct the original binary message and convert it to text.
5. Stop when the stopping character (“.”) is detected.

## Parameters

All parameters for send and receive are configurable in the `config.json` file.

### Sender Parameters
- `dest_port`: Destination port for DNS packets (default: 53).
- `bits_per_packet`: Number of bits encoded per packet (default: 2).
- `min_TTL`: Minimum TTL value (default: 1).
- `max_TTL`: Maximum TTL value (default: 255).
- `log_file_name`: Log file for saving sent messages.

### Receiver Parameters
- `dest_port`: Port to listen for DNS packets (default: 53).
- `bits_per_packet`: Number of bits decoded per packet (default: 2).
- `log_file_name`: Log file for saving received messages.

## Covert Channel Capacity
The covert channel capacity depends on the number of bits per packet and the total transmission time.

- Capacity with 1 bits per packet: **24.1 bit/sec**
- Capacity with 2 bits per packet: **48.5 bit/sec**
- Capacity with 4 bits per packet: **87.6 bit/sec**

## Observations
- The TTL range and modulo constraints restrict the channel's capacity.
- Increasing `bits_per_packet` improves capacity, but may increase detectability.

## How to Use the Experiment
1. Run `docker-compose up -d` in the main folder to create sender and receiver containers.
2. Open two terminals for the sender and receiver.
3. Enter the sender container:
    ```bash
    docker exec -it sender bash
    ```
4. Enter the receiver container:
    ```bash
    docker exec -it receiver bash
    ```
5. Navigate to the app folder on both terminals:
    ```bash
    cd ../app
    ```
6. Start the receiver to begin sniffing:
    ```bash
    make receive
    ```
7. Start the sender to send encoded messages:
    ```bash
    make send
    ```
8. Compare the logs to verify the transmission:
    ```bash
    make compare
    ```

## Notes
- Ensure that the TTL values remain within the specified range in `config.json`.
- `bits_per_second` can be selected as only 1, 2, and 4 because we want to send a single character with a certain number of packets.
- Make the `bits_per_second` and `dest_port` parameter exactly the same inside `send()` and `receive()` functions.
- When setting the range `[min_TTL, max_TTL]`, make sure that the range is bigger than number of different modulo values.
- Robust logging is implemented for debugging and validation purposes.
- Use the `make compare` command to confirm message accuracy.

## Conclusion
This project successfully demonstrates the use of DNS TTL fields for covert communication. The implementation adheres to project constraints while showcasing the potential of covert storage channels for secure and undetectable data transfer.
