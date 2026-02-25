# Use official Java image
FROM eclipse-temurin:21-jdk

# Set working directory
WORKDIR /app

# Copy source code
COPY src ./src

# Copy Gson library
COPY gson-2.13.2.jar .

# Compile Java files
RUN javac -cp gson-2.13.2.jar -d out $(find src -name "*.java")

# Expose default port
EXPOSE 8080

# Start the server
CMD ["sh", "-c", "java -cp out:gson-2.13.2.jar service.MainServer"]