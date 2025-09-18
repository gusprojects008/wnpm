
def packet_captured(pkt):
    if pkt.haslayer('DHCP') or pkt[DHCP].options[0][1] == 2:
       print(f"SERVER ON (; ===> :\n")
       pkt_info = pkt.show()
       print()
       #pkt[DHCP].options[1][1]
    else:
       print("DHCP OR GATEWAY SERVER NO RESPONSE ):")

       with StringIO() as stdout_buffer:
            sys.stdout = stdout_buffer

            print(f"SERVER DHCP AND BOOTP ON (; ===> :\n")
            packet.show()
            print('\n')

            packet_buffer_stored = stdout_buffer.getvalue()
            sys.stdout = sys.__stdout__
            print(packet_buffer_stored)
            print('\n')
print(f'{flags.error}{colors.bb} TYPE IT IP ADDRESS IPV4 VALID...{colors.reset}')
print(f'\n{flags.error}{colors.bb} IT WAS NOT POSSIBLE{colors.reset}')
print('\n{colors.error}{colors.blue} COULD TO NOT POSSIBLE SETUP OF THE ADDRESSES...{colors.reset}')
print('\n{colors.error}{colors.blue} SORRY ); COULD TO NOT POSSIBLE SETUP OF THE ADDRESSES... TRY MANUALLY{colors.reset}'
