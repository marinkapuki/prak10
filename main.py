from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import HTTPBasic, HTTPBasicCredentials

app = FastAPI()
security = HTTPBasic()

# Пример "базы данных" пользователей (для демонстрации)
fake_users_db = {
    "admin": "password123",
    "user": "secret"
}

def authenticate_user(credentials: HTTPBasicCredentials = Depends(security)):
    """Проверяет корректность учетных данных."""
    # Проверка имени пользователя
    user_password = fake_users_db.get(credentials.username)
    if user_password is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
            headers={"WWW-Authenticate": "Basic"}
        )
    
    # Проверка пароля
    if credentials.password != user_password:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
            headers={"WWW-Authenticate": "Basic"}
        )
    
    return credentials.username

@app.get("/login")
async def login(username: str = Depends(authenticate_user)):
    return {"message": "You got my secret, welcome"}
