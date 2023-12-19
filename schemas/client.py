def client_schema(item) -> dict:
    client_id = str(item.get("_id")) if "_id" in item else None
    email = item.get("email") if "email" in item else None
    return {
        "id": client_id,
        "username": item["username"],
        "email": email,
        "password": item["password"]
    }

def clients_schema(entity) -> list:
     return[client_schema(item) for item in entity]