import os, streamlit as st
from google import genai
from google.genai import types

client = genai.Client(
    api_key=os.environ["GEMINI_API_KEY"],
    http_options=types.HttpOptions(base_url=os.getenv("PRISMOR_PROXY", "http://127.0.0.1:7080")),
)

st.title("Gemini chat")
if "chat" not in st.session_state:
    st.session_state.chat = client.chats.create(model="gemini-3.6-flash")

for m in st.session_state.chat.get_history():
    if text := "".join(p.text or "" for p in m.parts):
        st.chat_message("user" if m.role == "user" else "assistant").write(text)

if prompt := st.chat_input("Ask something"):
    st.chat_message("user").write(prompt)
    st.chat_message("assistant").write_stream(
        c.text for c in st.session_state.chat.send_message_stream(prompt) if c.text
    )
