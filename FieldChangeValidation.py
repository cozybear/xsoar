#Get all users with sepcific role
allowed_role = 'Account Admin'
allowed_users = demisto.dt(demisto.executeCommand("getUsers", {"roles": allowed_role}), 'Contents.id')
args = demisto.args()
user_id = args.get('user', {}).get('id', {}) #Id of the user who attempted to change the field value
field_name = args.get('cliName', {})

#Check if allowed user performed the operation
if user_id and user_id not in allowed_users:
	demisto.log('Unauthorized user attempted to change the field value. Changing it back to the original value.') #log a message to Warroom
	demisto.executeCommand("setIncident", {field_name: args.get('old')}) #Changing the value back to the orginal one.s
