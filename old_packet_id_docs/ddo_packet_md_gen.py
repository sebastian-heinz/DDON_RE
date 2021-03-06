import json

with open('extracted.json', 'rt') as f:
    tables = json.loads(f.read())
    for table in tables:
        print(f"### {table['TableName']} (Table ID: {table['TableIdx']})")
        print(f"|Name|ID|Sub ID|Handler Address|")
        print(f"|---|---|---|---|")

        for h in table['Handlers']:
            print(f"|{h['PacketName']}|{h['ID']}|{h['SubID']}|{hex(h['CallbackPtr'])}|")
        
        print(f"---")