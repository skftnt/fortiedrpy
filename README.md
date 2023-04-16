# fortiedrpy
FortiEDR Python wrapper


Some Usage Examples:

    base_url = "https://agg1.ensilo.com"
    username = "restapi"
    password = "password"
    org = "Org Name (optional)"
    
    
    fortiedr = FortiEDRWrapper(base_url, username, password, org)
    
 How many times has the process WannaCry been detected?  
 
     proc = {"process": "wannacry"}
     process = fortiedr.count_events(proc)
     print(process)
     

Get a list of Events:

    params = {"collectorGroups": "Default Collector Group"}
    events = fortiedr.list_events(params)
    print(events)
