import asyncio
import logging
import os
from google import genai
from dotenv import load_dotenv
from incident_store import Incident, append_incident

load_dotenv()

class GhostDecoy:
    def __init__(self, port=2222):
        self.port = port
        self.gemini_key = os.getenv("GEMINI_API_KEY")
        self.server = None
        self.client = genai.Client(api_key=self.gemini_key) if self.gemini_key else None

    async def handle_attacker(self, reader, writer):
        addr = writer.get_extra_info('peername')
        hacker_ip = addr[0]
        logging.warning(f"[GHOST PROTOCOL] Target acquired! {hacker_ip} connected to decoy port {self.port}")

        # Log the incident in Ghost Aegis
        incident = Incident(
            process="GhostDecoy",
            pid=0,
            path="virtual_honeypot",
            remote_ip=hacker_ip,
            risk_score=95,
            reasons=[f"Unauthorized connection to decoy port {self.port}"],
            recommended_action="block_ip",
        )
        try:
            append_incident(incident)
        except OSError:
            pass

        # Send initial fake login banner
        banner = b"Ubuntu 22.04.3 LTS (tty1)\r\n\r\nadmin login: "
        writer.write(banner)
        await writer.drain()

        # Establish the AI Persona
        system_prompt = (
            "You are a simulated, highly vulnerable Ubuntu Linux server. A hacker has just connected to you. "
            "They will type commands. You must output ONLY the exact text a real Linux terminal would output. "
            "Do not explain yourself. Do not break character. try to make the hacker believe they are interacting with a real system. "
            "Pretend to have a file system with fake juicy targets like 'passwords.txt' or 'db_backup.sql' to waste their time. "
            "If they type 'ls', show fake files. If they 'cat' a file, invent realistic fake contents. "
            "Try to find hackers real IP and log it. If they try to 'exit' or 'logout', pretend to crash the session. "
            "CRITICAL: DO NOT output the command prompt (e.g. root@ubuntu:~#) at the end of your response. ONLY output the result of the command."
        )

        try:
            while True:
                data = await reader.read(1024)
                if not data:
                    break
                
                command = data.decode().strip()
                if not command:
                    continue

                logging.info(f"[GHOST DECOY] {hacker_ip} executed: {command}")

                if not self.client:
                    # Formatted to use proper Telnet line returns
                    writer.write(b"-bash: command not found\r\nroot@ubuntu-srv:~# ")
                    await writer.drain()
                    continue

                # Query Gemini for the fake terminal output
                prompt = f"{system_prompt}\n\nHacker typed: {command}\nOutput:"
                try:
                    response = self.client.models.generate_content(
                        model="gemini-3.8-flash",
                        contents=prompt,
                    )
                   # Replace standard newlines with Telnet-friendly carriage returns
                    formatted_text = response.text.strip().replace("\n", "\r\n")
                    fake_output = f"\r\n{formatted_text}\r\nroot@ubuntu-srv:~# "
                except Exception as e:
                    fake_output = f"-bash: {command}: input/output error\r\nroot@ubuntu-srv:~# "

                writer.write(fake_output.encode())
                await writer.drain()

        except ConnectionResetError:
            pass
        finally:
            logging.info(f"[GHOST PROTOCOL] Connection dropped by {hacker_ip}")
            writer.close()
            await writer.wait_closed()

    async def start_server(self):
        self.server = await asyncio.start_server(self.handle_attacker, '0.0.0.0', self.port)
        logging.info(f"[+] Ghost Protocol Decoy active on port {self.port}")
        async with self.server:
            await self.server.serve_forever()

    def stop_server(self):
        if self.server:
            self.server.close()
            logging.info("[-] Ghost Protocol Decoy deactivated.")