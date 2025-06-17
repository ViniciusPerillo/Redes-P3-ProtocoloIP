from iputils import *
import ipaddress 



class IP:
    def __init__(self, enlace):
        """
        Inicia a camada de rede. Recebe como argumento uma implementação
        de camada de enlace capaz de localizar os next_hop (por exemplo,
        Ethernet com ARP).
        """
        self.callback = None
        self.enlace = enlace
        self.enlace.registrar_recebedor(self.__raw_recv)
        self.ignore_checksum = self.enlace.ignore_checksum
        self.meu_endereco = None
        self.counter = 0

    def __raw_recv(self, datagrama):
        dscp, ecn, identification, flags, frag_offset, ttl, proto, \
           src_addr, dst_addr, payload = read_ipv4_header(datagrama)
        if dst_addr == self.meu_endereco:
            # atua como host
            if proto == IPPROTO_TCP and self.callback:
                self.callback(src_addr, dst_addr, payload)
        else:
            # atua como roteador
            next_hop = self._next_hop(dst_addr)
            # TODO: Trate corretamente o campo TTL do datagrama
            ttl -= 1
            
            if ttl == 0:
                next_hop = self._next_hop(src_addr)

                header = build_ip_header(
                    version= 4, 
                    ihl= 5, 
                    dscp= dscp, 
                    ecn = ecn, 
                    length= 532, 
                    id= identification, 
                    flags= flags, 
                    frag= frag_offset, 
                    ttl= 64, 
                    protocol= IPPROTO_ICMP, 
                    s_addr= int(ipaddress.IPv4Address(self.meu_endereco)),
                    d_addr= int(ipaddress.IPv4Address(src_addr))
                )

                segmento = build_ttl_exceded_icmp_header(
                    type= 11,
                    code= 0,
                    datagrama= datagrama
                )

                datagrama = header + segmento

                self.enlace.enviar(datagrama, next_hop)
            else:

                header = build_ip_header(
                    version= 4, 
                    ihl= 5, 
                    dscp= dscp, 
                    ecn = ecn, 
                    length= len(payload) + 20, 
                    id= identification, 
                    flags= flags, 
                    frag= frag_offset, 
                    ttl= ttl, 
                    protocol= proto, 
                    s_addr= int(ipaddress.IPv4Address(src_addr)),
                    d_addr= int(ipaddress.IPv4Address(dst_addr))
                )

                segmento = datagrama[20:]
                datagrama = header + segmento

                self.enlace.enviar(datagrama, next_hop)

    def _next_hop(self, dest_addr):
        # TODO: Use a tabela de encaminhamento para determinar o próximo salto
        # (next_hop) a partir do endereço de destino do datagrama (dest_addr).
        # Retorne o next_hop para o dest_addr fornecido.

        bin_dest_addr = bin(int(ipaddress.IPv4Address(dest_addr)))[2:].rjust(32, '0')
        for i in range(32, -1, -1):
            try: 
                next_hop = self.tabela[i][bin_dest_addr[:i]]
            except KeyError:
                pass
            else:
                return next_hop

        return None

    def definir_endereco_host(self, meu_endereco):
        """
        Define qual o endereço IPv4 (string no formato x.y.z.w) deste host.
        Se recebermos datagramas destinados a outros endereços em vez desse,
        atuaremos como roteador em vez de atuar como host.
        """
        self.meu_endereco = meu_endereco

    def definir_tabela_encaminhamento(self, tabela):
        """
        Define a tabela de encaminhamento no formato
        [(cidr0, next_hop0), (cidr1, next_hop1), ...]

        Onde os CIDR são fornecidos no formato 'x.y.z.w/n', e os
        next_hop são fornecidos no formato 'x.y.z.w'.
        """
        # TODO: Guarde a tabela de encaminhamento. Se julgar conveniente,
        # converta-a em uma estrutura de dados mais eficiente.
        
        self.tabela = {i: dict() for i in range(32, -1, -1)}

        for cidr, next_hop in tabela:
            address, n_bits_fixos = cidr.split('/')
            n_bits_fixos = int(n_bits_fixos)
            bin_adrress = bin(int(ipaddress.IPv4Address(address)))[2:].rjust(32, '0')[:n_bits_fixos]
            self.tabela[n_bits_fixos] |= {bin_adrress: next_hop}

        pass

    def registrar_recebedor(self, callback):
        """
        Registra uma função para ser chamada quando dados vierem da camada de rede
        """
        self.callback = callback

    def enviar(self, segmento, dest_addr):
        """
        Envia segmento para dest_addr, onde dest_addr é um endereço IPv4
        (string no formato x.y.z.w).
        """
        next_hop = self._next_hop(dest_addr)
        # TODO: Assumindo que a camada superior é o protocolo TCP, monte o
        # datagrama com o cabeçalho IP, contendo como payload o segmento.
        length = len(segmento)  # 20 bytes de cabeçalho IP
        header = build_ip_header(
            version= 4, 
            ihl= 5, 
            dscp= 0, 
            ecn = 0, 
            length= 20+length , 
            id= self.counter, 
            flags= 0, 
            frag= 0, 
            ttl= 64, 
            protocol= IPPROTO_TCP, 
            s_addr= int(ipaddress.IPv4Address(self.meu_endereco)),
            d_addr= int(ipaddress.IPv4Address(dest_addr))
        )

        datagrama = header + segmento
        self.counter += 1

        self.enlace.enviar(datagrama, next_hop)

def build_ip_header(*, version, ihl, dscp, ecn, length, id, flags, frag, ttl, protocol, s_addr, d_addr):
    before_checksum = version<<76 | ihl<<72 | dscp<<66 |ecn<<64 | length<<48 | id<<32 | flags<<29 | frag<<16 | ttl<<8 | protocol # 80 bits
    checksum = calc_checksum((before_checksum<<80 | 0<<64 | s_addr<<32 | d_addr).to_bytes(20, 'big'))
    header = before_checksum<<80 | checksum<<64 | s_addr<<32 | d_addr
    
    return header.to_bytes(20, 'big')

def build_ttl_exceded_icmp_header(*, type, code, datagrama):
    before_checksum = type<<8 | code
    checksum = calc_checksum((before_checksum<<48 | 0<<32 | 0).to_bytes(8, 'big') + datagrama[:416])
    header = (before_checksum<<48 | checksum<<32 | 0).to_bytes(8, 'big') + datagrama[:416]

    return header
