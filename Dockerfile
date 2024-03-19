# Use a base image with the JDK and Maven to compile and run the Java application
FROM maven:3.8.1-openjdk-11-slim AS build

# Set the working directory in the container
WORKDIR /workspace

# Copy the Java source code and pom.xml into the container
COPY HelloWorld.java pom.xml ./

# Compile the Java source code into a class file
RUN mvn package

# Use a smaller base image for the final image
FROM adoptopenjdk/openjdk11:alpine-jre

# Set the working directory in the final image
WORKDIR /workspace

# Copy the compiled JAR file from the build stage to the final image
COPY --from=build /app/target/HelloWorld-1.0-SNAPSHOT.jar /app/target/HelloWorld.jar

# Specify the command to run on container startup
CMD ["java", "-jar", "HelloWorld.jar"]
