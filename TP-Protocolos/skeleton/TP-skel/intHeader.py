from scapy.all import *
import sys, os

TYPE_IPV4 = 0x800
TYPE_INT_PAI = 0x1212

class int_pai(Packet):
    fields_desc = [ BitField("Qtd_Filhos", 0, 32),
                    BitField("Estouro_MTU", 0, 8)
                    ]

class int_filho(Packet):
    fields_desc = [ BitField("Id_switch", 0, 32),
                    BitField("Porta_Entrada", 0, 9),
                    BitField("Porta_Saida", 0, 9),
                    BitField("Timestamp", 0, 48),
                    BitField("Padding", 0, 6)]

bind_layers(Ether, int_pai, type=TYPE_INT_PAI)
bind_layers(int_pai,IP, Qtd_Filhos=0)
bind_layers(int_pai, int_filho)
bind_layers(int_filho,int_filho, Padding=0)
bind_layers(int_filho,IP,Padding=1)
