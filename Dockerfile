# Use a base image with the JDK to compile and run the Java application
FROM adoptopenjdk/openjdk11:alpine-slim AS build

# Set the working directory in the container
WORKDIR /app

# Copy the Java source code and pom.xml into the container
COPY HelloWorld.java pom.xml ./

# Compile the Java source code into a class file
RUN mvn package


