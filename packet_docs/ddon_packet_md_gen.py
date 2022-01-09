import json
import os
import sys

with open('ddon_game_packet_handler_dump_notated.json', 'rt', encoding='utf8') as f:
    handler_dump = json.loads(f.read())


with open('GamePackets.md', 'wt', encoding='utf8') as f:
    f.write('# DDON Game Server Packets (v03.04.007)\n\n')

    f.write("## Tables\n")
    for group in handler_dump:
        if group['GroupName'] is not None:
            f.write(f"### Group: {group['GroupID']} - ({group['GroupName']})\n")
        else:
            f.write(f"### Group: {group['GroupID']}\n")

        f.write(f"|Name|GroupID|ID|Sub ID|Handler Address|Comment|\n")
        f.write(f"|---|---|---|---|---|---|\n")

        for handler in group['Handlers']:
            if handler['SubID'] == 2:
                # Response packet, forge request packet :)
                #'abc_5_0_2_RES'.replace('5_0_2', '5_0_1').removesuffix('_RES') + '_REQ'
                req_ver_string = f"{group['GroupID']}_{handler['ID']}_1"
                res_ver_string = f"{group['GroupID']}_{handler['ID']}_{handler['SubID']}"
                req_pname = handler['PacketName'].replace(res_ver_string, req_ver_string)
                req_pname = req_pname.removesuffix('_RES') + '_REQ'
                req_pname = req_pname.replace('S2C', 'C2S')
                f.write(f"|{req_pname}|{group['GroupID']}|{handler['ID']}|1|N/A||\n")

            output_pname = handler['PacketName']
            if handler['SubID'] == 16 and not output_pname.endswith('_NTC'):
                output_pname += '_NTC'

            if handler['SubID'] == 2 and not output_pname.endswith('_RES'):
                output_pname += '_RES'


            f.write(f"|{output_pname}|{group['GroupID']}|{handler['ID']}|{handler['SubID']}|{hex(handler['HandlerAddr'])}|{handler['HandlerComment']}|\n")
            


        f.write('\n\n')


    f.write("## Auto-generated C# code\n")
    f.write('```cs\n')
    for group in handler_dump:
        if group['GroupName'] is not None:
            f.write(f"// Group: {group['GroupID']} - ({group['GroupName']})\n")
        else:
            f.write(f"// Group: {group['GroupID']}\n")

        for handler in group['Handlers']:
            if handler['SubID'] == 2:
                # Response packet, forge request packet :)
                #'abc_5_0_2_RES'.replace('5_0_2', '5_0_1').removesuffix('_RES') + '_REQ'
                req_ver_string = f"{group['GroupID']}_{handler['ID']}_1"
                res_ver_string = f"{group['GroupID']}_{handler['ID']}_{handler['SubID']}"
                req_pname = handler['PacketName'].replace(res_ver_string, req_ver_string)
                req_pname = req_pname.removesuffix('_RES') + '_REQ'
                req_pname = req_pname.replace('S2C', 'C2S')
                f.write(f"public static readonly PacketId {req_pname} = new PacketId({group['GroupID']}, {handler['ID']}, 1, \"{req_pname}\");\n")

            output_pname = handler['PacketName']
            if handler['SubID'] == 16 and not output_pname.endswith('_NTC'):
                output_pname += '_NTC'

            if handler['SubID'] == 2 and not output_pname.endswith('_RES'):
                output_pname += '_RES'


            if 'HandlerComment' in handler and handler['HandlerComment'] is not None:
                f.write(f"public static readonly PacketId {output_pname} = new PacketId({group['GroupID']}, {handler['ID']}, {handler['SubID']}, \"{output_pname}\"); // {handler['HandlerComment']}\n")
            else:
                f.write(f"public static readonly PacketId {output_pname} = new PacketId({group['GroupID']}, {handler['ID']}, {handler['SubID']}, \"{output_pname}\");\n")

        f.write('\n')
    f.write('```\n')


    f.write('```cs\n')     
    f.write('private static Dictionary<int, PacketId> InitializeGamePacketIds()\n')
    f.write("{\n") 
    f.write("Dictionary<int, PacketId> packetIds = new Dictionary<int, PacketId>();\n") 
    f.write("AddPacketIdEntry(packetIds, UNKNOWN);\n") 
    for group in handler_dump:
        if group['GroupName'] is not None:
            f.write(f"// Group: {group['GroupID']} - ({group['GroupName']})\n")
        else:
            f.write(f"// Group: {group['GroupID']}\n")

        for handler in group['Handlers']:
            if handler['SubID'] == 2:
                # Response packet, forge request packet :)
                #'abc_5_0_2_RES'.replace('5_0_2', '5_0_1').removesuffix('_RES') + '_REQ'
                req_ver_string = f"{group['GroupID']}_{handler['ID']}_1"
                res_ver_string = f"{group['GroupID']}_{handler['ID']}_{handler['SubID']}"
                req_pname = handler['PacketName'].replace(res_ver_string, req_ver_string)
                req_pname = req_pname.removesuffix('_RES') + '_REQ'
                req_pname = req_pname.replace('S2C', 'C2S')
                f.write(f"AddPacketIdEntry(packetIds, {req_pname});\n") 

            output_pname = handler['PacketName']
            if handler['SubID'] == 16 and not output_pname.endswith('_NTC'):
                output_pname += '_NTC'

            if handler['SubID'] == 2 and not output_pname.endswith('_RES'):
                output_pname += '_RES'

            f.write(f"AddPacketIdEntry(packetIds, {output_pname});\n")
        f.write('\n')
    f.write('return packetIds;\n')          
    f.write('}\n')          
    f.write('```\n')



    """
    for table in tables:
        print(f"### {table['TableName']} (Table ID: {table['TableIdx']})")
        print(f"|Name|ID|Sub ID|Handler Address|")
        print(f"|---|---|---|---|")

        for h in table['Handlers']:
            print(f"|{h['PacketName']}|{h['ID']}|{h['SubID']}|{hex(h['CallbackPtr'])}|")
        
        print(f"---")

    """
