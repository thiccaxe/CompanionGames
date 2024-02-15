"""
CompanionGames
Copyright (C) 2024 thiccaxe

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as published
by the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
"""


"""
Plan for the games server:

- Games Server publishes MDNS records.
- Games Server runs TCP server for companion remote protocol.
- Games Server runs WebSocket server.
- Website connects to Games Server using websocket.
  - Supposing that at some point the websocket may be secured by TLS, the website and games server should exchange a
    secret to verify the connection.
- The Games Server is intended to be used with 1 connected website at a time.
- Website can command Games Server to:
  - Create a pairing session. Pairing session allows ios clients to pair to games server using companion remote protocol.
     - A pairing session may only be active when the website is connected to the games serveer
     - Pairing session can be configured to allow a set amount of clients to pair, or an unlimited amount.
     - If a client is already paired, it may not pair again
        - A client is identified by its <iOSDevicePairingID>. if a pairing session is open, the <iOSDevicePairingID>
            is not recieved by the Games Server unless the client is already attempting to pair to the Games Server.
            Since the <iOSDevicePairingID> can be spoofed at this point, the games server shall immediately close the 
            current pairing attempt by the client. The client must be removed through the proper mechanism, if it truly
            needs to re-pair.
            - The Games Server shall use some transformation to mask the true <iOSDevicePairingID> of the client.
              - The transformation shall be unique across various instances of the Games Server.
              - For the website, the <iOSDevicePairingID> shall not be recoverable from the masked version reported.
     - When creating a pairing session, the Games Server reports the pin code to the website.
        - The Games Server may generate the pin codes if not supplied by the website.
     - There may be multiple pairing sessions active at the same time. For practicality, there ought to be no more than 3 
     - A pairing session shall have a random id
     - No two pairing sessions may use the same pin code at the same time. The Games Server shall not change
         pin codes requested by the website when creating the pairing session, and instead report an error, and not 
         proceed to construct the pairing session.
     - When a pairing session is active, other game activity proceeding on the website MUST be paused. The games Server
         cannot enforce this, but assumes as such, and will not forward any client inputs to the server.
         - When pairing is done, and gameplay is to continue, the pairing session MUST be stopped.
     - A pairing session that is stopped may not be restarted.
     - A pairing session may be designated as an "admin" pairing session. When clients pair to the Games Server using
         the host pairing session, they will be permanently designated as an "admin" until the pairing is removed. 
         This pairing session is special and makes some exceptions to the above requirements.
         - The "admin" pairing session is active, unless explicity closed, or the website disconnects
         - If a client uses the "admin" pairing session, it may repair.
         - The "admin" pairing session is designated for clients who need to setup and control the website, including actions such as:
             - opening/closing pairing sessions
             - Starting, Stopping, Pausing, Configuring, and Setting Up Games
             - Media controls
  - Stop a pairing session
  - Respond with a list of connected clients
  - Respond with a list of paired clients
  - Listen to events, such as when a client is paired, connected, disconnected
  - Listen to to events from a specific client, such as:
    - Button actions for all or specific buttons (press, release)
    - Location events from the touch pad
    - Press events from the touch pad
  - The website may create a typing session.
    - A client may only have one typing session assigned to it at any given time.
    - A typing session may only be assigned to one client at any given time.
    - A typing session has a random id.
    - A typing session has linked to it some string of text.
    - A typing session may be pre-configured with text on creation.
    - the website may update the current text of the typing session.
    - When clients update the text in the typing session, the website will recieve the updates.
    - When clients perform certain actions, such as a "submission" action or a "cancel" action, the website shall be
      notified.
      - When a client cancels the typing session, it shall be dissociated from the client.
      - If the website is not satisfied with the current state of the typing session, especially the text of it, 
        it may reassign the typing session to the client which cancelled it. 
    - The website may reassign the typing session to a client. 
    - If a client disconnects from the games server, the website will recieve the usual disconnect event (if it has
       subscribed to that type of event for the client or globally), and will also in addition recieve an event linked
       to the typing session, notifying the website about the client disconnect. At this point, the typing session is
       dissociated from the client that disconnected.
    - If the website wishes to create a typing session associated with multiple
    
- Games Server parses companion remote protocol data, selects what the website has requested to listen to, appends
  proper metadata (such as typing session id, client id (masked)) and forwards it to the website using the websocket
  connection.
- In the case that the website disconnects from the games server,
    - the games server will shutdown all pairing sessions (including the admin session)
       - in any close of pairing session, any client currently in the process of pairing shall immediately be disconnected
    - the games server will close all typing sessions. Further more, all typing sessions will be deleted.
    - The games server will retain other session data.


"""