## Tool Methodology

Here will be covered tools that we will be using during the course. The following material is not a documentation of the tools, it supposed to give the reader Red Team mentality and help him to understand **what** is he doing and **why** not just **how**.

#### **Targets**

What Labs will be used for the methodology and how to set them up.

##### **DVWA (Damn Vulnerable Web Application)**

The target is deployed locally using **Docker** for isolation and repeatability.

1.  **Install Docker:**
    
    ```
    sudo dnf install docker docker-compose -y
    sudo systemctl enable --now docker
    sudo usermod -aG docker $USER 
    ```
    
    Log out and back in.
2.  **Pull and run DVWA:**
    
    ```sh
    docker run -d -p 8080:80 vulnerables/web-dvwa #use another port if port 8080 is not available
    ```
3.  **Open it:**
    
    Go to: `http://localhost:8080`
4.  **Login and Setup:**
    
    **user:** admin
    
    **password:** password
    
    Click **Create / Reset Database**.  
    Then **DVWA Security → Low/Medium/High/Impossible**
