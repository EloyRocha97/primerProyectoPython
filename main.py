from fastapi import FastAPI
from routes.client import client


app = FastAPI()

# iniciar el server: uvicorn main:app --reload
# localhost: http://127.0.0.1:8000

app.include_router(client)
