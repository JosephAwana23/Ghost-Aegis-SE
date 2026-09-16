import requests

def check_breach(target_email):
    # Using XposedOrNot's free keyless API for breach checks
    url = f"https://api.xposedornot.com/v1/check-email/{target_email}"
    
    try:
        response = requests.get(url, timeout=5)
        
        # HTTP 404 means the email was NOT found in any breaches (Safe)
        if response.status_code == 404:
            return {"exposed": False, "details": f"{target_email} is clean. No breaches found."}
            
        # HTTP 200 means the email WAS found in a breach
        if response.status_code == 200:
            data = response.json()
            breaches = data.get("breaches", [])
            
            # Flatten the list if the API nests it unexpectedly
            if isinstance(breaches, list) and len(breaches) > 0 and isinstance(breaches[0], list):
                breaches = breaches[0]
                
            breach_count = len(breaches)
            
            # FIX: If the API connects but returns an empty list, flag as Safe!
            if breach_count == 0:
                return {"exposed": False, "details": f"{target_email} is clean. No breaches found."}
            
            # Grab the first 3 breach names for the incident report
            breach_names = ", ".join(breaches[:3]) 
            
            details = f"{target_email} found in {breach_count} breaches (e.g., {breach_names})."
            return {"exposed": True, "details": details}
            
        return {"error": f"Unexpected API response: {response.status_code}"}
        
    except requests.exceptions.RequestException as e:
        return {"error": str(e)}