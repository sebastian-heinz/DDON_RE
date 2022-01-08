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

        f.write(f"|Name|GroupID|ID|Sub ID|Handler Address|Handler Comment|\n")
        f.write(f"|---|---|---|---|---|---|\n")

        for handler in group['Handlers']:
            f.write(f"|{handler['PacketName']}|{group['GroupID']}|{handler['ID']}|{handler['SubID']}|{hex(handler['HandlerAddr'])}|{handler['HandlerComment']}|\n")
            


        f.write('\n\n')


    f.write("## Auto-generated C# code\n")
    f.write('```cs\n')
    for group in handler_dump:
        if group['GroupName'] is not None:
            f.write(f"// Group: {group['GroupID']} - ({group['GroupName']})\n")
        else:
            f.write(f"// Group: {group['GroupID']}\n")

        for handler in group['Handlers']:
            #public static readonly PacketId L2C_GP_COURSE_GET_INFO_RES = new PacketId(4, 0, 2, "L2C_GP_COURSE_GET_INFO_RES");
            if 'HandlerComment' in handler and handler['HandlerComment'] is not None:
                f.write(f"public static readonly GameServerPacketId {handler['PacketName']} = new PacketId({group['GroupID']}, {handler['ID']}, {handler['SubID']}, \"{handler['PacketName']}\"); // {handler['HandlerComment']}\n")
            else:
                f.write(f"public static readonly GameServerPacketId {handler['PacketName']} = new PacketId({group['GroupID']}, {handler['ID']}, {handler['SubID']}, \"{handler['PacketName']}\");\n")

        f.write('\n')

    f.write('```')
        






    """
    for table in tables:
        print(f"### {table['TableName']} (Table ID: {table['TableIdx']})")
        print(f"|Name|ID|Sub ID|Handler Address|")
        print(f"|---|---|---|---|")

        for h in table['Handlers']:
            print(f"|{h['PacketName']}|{h['ID']}|{h['SubID']}|{hex(h['CallbackPtr'])}|")
        
        print(f"---")

    """