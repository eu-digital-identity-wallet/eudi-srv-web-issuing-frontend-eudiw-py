FROM python:3.13.12-slim

# Set working directory
WORKDIR /app

# Copy all files
COPY . .

# Install system dependencies for Python and Node.js
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    build-essential \
    ca-certificates \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install Node.js (LTS) and npm
RUN curl -fsSL https://deb.nodesource.com/setup_lts.x | bash - \
    && apt-get install -y nodejs \
    && rm -rf /var/lib/apt/lists/*

# Upgrade pip
RUN python -m pip install --upgrade pip

# Install Python dependencies
RUN pip install --no-cache-dir -r app/requirements.txt

# Install frontend dependencies and build
RUN npm install
RUN npm run build

# Set Flask environment
ENV FLASK_APP=app

# Expose Flask port
EXPOSE 5000

# Run Flask
CMD ["flask", "run", "--host=0.0.0.0"]
