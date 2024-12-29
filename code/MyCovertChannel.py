from CovertChannelBase import CovertChannelBase
from scapy.all import IP, UDP, DNS, DNSQR, DNSRR, sniff
import random
import time

class MyCovertChannel(CovertChannelBase):
    """
    Implements TTL Modulo Encoding.
    """
    def __init__(self):
        super().__init__()

    def generate_ttl_with_modulo(self, modulo_value, min_TTL, max_TTL, modulo_base):
        """
        - This function generates a TTL value that satisfies a specific modulo constraint.
        - The TTL value is randomly selected within the range [min_TTL, max_TTL].
        - The modulo difference is calculated to adjust the TTL value to meet the modulo condition (TTL % modulo_base == modulo_value).
        - Adjustments ensure the TTL remains within the specified range.
        - An assertion checks that the generated TTL satisfies the required modulo condition.
        - Returns the calculated TTL value.
        """

        random_TTL = random.randint(min_TTL, max_TTL)  # Start with a random value in the range
        modulo_diff = (random_TTL % modulo_base) - modulo_value
        random_TTL -= modulo_diff  # Adjust the random_TTL value to satisfy the modulo constraint
        if random_TTL < min_TTL:
            random_TTL += modulo_base
        elif random_TTL > max_TTL:
            random_TTL -= modulo_base
        
        assert random_TTL % modulo_base == modulo_value, f"Invalid TTL value: {random_TTL}"
        return random_TTL
        
        

    def send(self, log_file_name, dest_port, bits_per_packet = 2,  min_TTL = 1, max_TTL = 255):
        """
        - This function handles the sending of messages using TTL Modulo Encoding.
        - A random binary message is generated and logged using the base class function.
        - The message is divided into chunks of `bits_per_packet` size.
        - Each chunk is converted to a modulo value, which is then used to calculate a TTL that satisfies the modulo constraint.
        - DNS packets are created with the calculated TTL and sent to the receiver.
        - A short delay (time.sleep) is added between packet transmissions to prevent packet loss.
        """

        # Generate random binary message and log it
        binary_message = self.generate_random_binary_message_with_logging(log_file_name)
        
        
        ttl_values = []
        # Encode bits_per_packet bits per TTL using modulo constraints
        #start = time.time()
        for i in range(0, len(binary_message), bits_per_packet):
            bits_to_be_encoded = binary_message[i:i + bits_per_packet]

            modulo_value = int(bits_to_be_encoded, 2)  # Convert bits_per_packet bits to a modulo value 
            ttl_value = self.generate_ttl_with_modulo(modulo_value, min_TTL = min_TTL, max_TTL = max_TTL, modulo_base = 2 ** bits_per_packet)
            ttl_values.append(ttl_value)

            # Create and send DNS packet with encoded TTL
            packet = IP(dst="receiver") / UDP(dport = dest_port) / DNS(
                an=DNSRR(ttl=ttl_value)
            )
            super().send(packet)
            time.sleep(0.02)  # Wait for a short time between packets
            
        #end = time.time()
        #print("Capacity bits/sec: ", 128/(end - start))  

    def receive(self, log_file_name, dest_port, bits_per_packet = 2):
        """
        - This function handles the receiving and decoding of messages.
        - Captures DNS packets, extracts the TTL field, and decodes the message based on the modulo constraint.
        - The TTL modulo value is converted back to its binary representation and appended to the binary message.
        - Checks for a termination character ("."), and stops sniffing when it's detected.
        - Reconstructs the binary message and converts it back into the original string message.
        - Logs the decoded message to the specified log file.
        """
        ttl_values = []
        binary_message = []

        termination_detected = False
        modulo_base = 2 ** bits_per_packet
        packet_per_char = 8 // bits_per_packet
        format_string = f'0{bits_per_packet}b'

        def packet_callback(packet):
            nonlocal termination_detected
            if packet.haslayer(DNSRR):
                ttl_value = packet[DNSRR].ttl
                ttl_values.append(ttl_value)

                # Decode bits_per_packet bits from TTL modulo_base
                decoded_bits = format(ttl_value % modulo_base, format_string)
                binary_message.append(decoded_bits)
                
                # Check for termination
                if len(binary_message) % packet_per_char == 0:
                    last_char = ''.join(binary_message[-packet_per_char:])
                    if self.convert_eight_bits_to_character(last_char) == ".":
                        termination_detected = True
                        return False  # Stops sniffing

        # Capture DNS packets until termination is detected
        while not termination_detected:
            sniff(filter=f"udp and port {dest_port}", prn=packet_callback, count=1)

        # Reconstruct the binary message
        binary_message_str = ''.join(binary_message)

        # Convert binary back to the original message
        received_message = ''.join(
            self.convert_eight_bits_to_character(binary_message_str[i:i + 8])
            for i in range(0, len(binary_message_str), 8)
        )

        # Log the decoded message
        self.log_message(f"{received_message}", log_file_name)
