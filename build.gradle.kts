import org.jetbrains.kotlin.gradle.dsl.JvmTarget

plugins {
    kotlin("jvm") version "2.3.21"
    kotlin("plugin.serialization") version "2.3.21"
    id("com.gradleup.shadow") version "9.0.0"
}

group = "com.deadbife"
version = "1.0.0"

repositories {
    mavenCentral()
}

val montoyaVersion = project.property("montoyaVersion") as String

dependencies {
    compileOnly("net.portswigger.burp.extensions:montoya-api:$montoyaVersion")
    // Parseo de los .map (JSON). Es la unica dependencia empaquetada.
    implementation("org.jetbrains.kotlinx:kotlinx-serialization-json:1.8.1")
}

// Compila con el JDK del sistema (26) apuntando a bytecode 17, el minimo de Montoya.
java {
    sourceCompatibility = JavaVersion.VERSION_17
    targetCompatibility = JavaVersion.VERSION_17
}

kotlin {
    compilerOptions {
        jvmTarget.set(JvmTarget.JVM_17)
    }
}

tasks.shadowJar {
    archiveClassifier.set("all")
    mergeServiceFiles()
}

tasks.build {
    dependsOn(tasks.shadowJar)
}
