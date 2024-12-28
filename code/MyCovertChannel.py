from CovertChannelBase import CovertChannelBase
from scapy.all import IP, UDP, DNS, DNSQR, DNSRR, sniff
import random
import time

class MyCovertChannel(CovertChannelBase):
    """
    Implements TTL Modulo Encoding with random TTL values satisfying modulo constraints.
    """
    def __init__(self):
        super().__init__()

    def generate_ttl_with_modulo(self, modulo_value):
        """
        Generates a TTL value whose modulo 4 is equal to the specified value.
        :param modulo_value: The target modulo value (0, 1, 2, 3).
        :return: A TTL value satisfying the modulo constraint.
        """
        base = random.randint(128, 255)  # Start with a random value in the range
        modulo_diff = (base % 4) - modulo_value
        base -= modulo_diff  # Adjust the base value to satisfy the modulo constraint
        if base < 128:
            base += 4
        elif base > 255:
            base -= 4
        
        assert base % 4 == modulo_value, f"Invalid TTL value: {base}"
        return base
        
        

    def send(self, log_file_name, p1):
        """
        Encodes the message using TTL Modulo Encoding with random TTL values and transmits it.
        :param log_file_name: File to log the operation.
        """
        # Generate random binary message and log it
        binary_message = self.generate_random_binary_message_with_logging(log_file_name)
        
        
        ttl_values = []
        # Encode 2 bits per TTL using modulo constraints
        start = time.time()
        for i in range(0, len(binary_message), 2):
            bits_to_be_encoded = binary_message[i:i + 2]
            print(bits_to_be_encoded)

            modulo_value = int(bits_to_be_encoded, 2)  # Convert 2 bits to a modulo value (0-3)
            ttl_value = self.generate_ttl_with_modulo(modulo_value)
            ttl_values.append(ttl_value)

            # Create and send DNS packet with encoded TTL
            packet = IP(dst="receiver") / UDP(dport=53) / DNS(
                an=DNSRR(ttl=ttl_value)
            )
            super().send(packet)
            time.sleep(0.02)  # Wait for a short time between packets
            
        end = time.time()
        print("Capacity bits/sec: ", 128/(end - start))  

    def receive(self, log_file_name, p1):
        """
        Decodes the message by extracting TTL Modulo Encoding from received packets.
        :param receiver_ip: IP address of the receiver.
        :param log_file_name: File to log the operation.
        :param count: Number of packets to capture.
        """
        ttl_values = []
        binary_message = []

        termination_detected = False

        def packet_callback(packet):
            nonlocal termination_detected
            if packet.haslayer(DNSRR):
                ttl_value = packet[DNSRR].ttl
                ttl_values.append(ttl_value)

                # Decode 2 bits from TTL modulo 4
                decoded_bits = format(ttl_value % 4, '02b')
                binary_message.append(decoded_bits)
                print(decoded_bits)
                
                # Check for termination
                if len(binary_message) % 4 == 0:
                    last_char = ''.join(binary_message[-4:])
                    print(self.convert_eight_bits_to_character(last_char))
                    if self.convert_eight_bits_to_character(last_char) == ".":
                        termination_detected = True
                        return False  # Stops sniffing

        # Capture DNS packets until termination is detected
        while not termination_detected:
            sniff(filter=f"udp and port 53", prn=packet_callback, count=1)

        # Reconstruct the binary message
        binary_message_str = ''.join(binary_message)

        # Convert binary back to the original message
        received_message = ''.join(
            self.convert_eight_bits_to_character(binary_message_str[i:i + 8])
            for i in range(0, len(binary_message_str), 8)
        )

        # Log the decoded message
        self.log_message(f"{received_message}", log_file_name)
