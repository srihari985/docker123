# Use a base image with the JDK to compile and run the Java application
FROM adoptopenjdk/openjdk11:alpine-slim AS build

# Set the working directory in the container
WORKDIR /app

# Copy the Java source code and pom.xml into the container
COPY HelloWorld.java pom.xml ./

# Compile the Java source code into a class file
RUN javac HelloWorld.java

# Package the Java application into a JAR file
RUN  package

# Use a smaller base image for the runtime environment
FROM adoptopenjdk/openjdk11:alpine-jre

# Set the working directory in the container
WORKDIR /app

# Copy the compiled JAR file from the build image
COPY --from=build /app/target/HelloWorld-1.0-SNAPSHOT.jar .

# Run the Java application
CMD ["java", "-jar", "HelloWorld-1.0-SNAPSHOT.jar"]
