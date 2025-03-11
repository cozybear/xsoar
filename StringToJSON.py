regex_groups = re.findall("\\{.*?\\}", asset_details[0])

for group in regex_groups:
	inp = group.replace('\'', '"')
	try:
	    data = json.loads(inp)
	except json.JSONDecodeError as e:
	    print(f"Error while parsing JSON: {e}")
	    data = {}
	    
	for k,v in data.items():
	    if isinstance(v, (int,float)):
	        data[k] = str(v)
	data = str(str(data).replace('\'', '"'))

	json_final = json.loads(data)
	json_to_display['Assets'].append(json_final)
	
