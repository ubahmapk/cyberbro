# Utilise une image Python de base
FROM python:3.11-slim

# Définis le répertoire de travail dans le conteneur
WORKDIR /app

# Copie les fichiers requirements.txt et .gitignore dans le conteneur
COPY requirements.txt .

# Installe les dépendances
RUN pip install --no-cache-dir -r requirements.txt

# Copie le reste des fichiers de ton projet dans le conteneur
COPY . .

# Expose le port 5000
EXPOSE 5000

# Commande pour exécuter l'application
CMD ["python", "app.py"]
