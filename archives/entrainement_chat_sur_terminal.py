import openai
openai.api_key = "ma cle API"

messages = []
system_msg = input("A quel type de personne voudriez-vous vous adresser ? etudiant ? enseignant ? conseiller en orientation ? \n")
messages.append({"role": "system", "content": system_msg})

print("Ok, notre assistant est pret pour repondre 'a vos questions. Comment puis-je vous aider ?")

while input != "exit" :
    message = input()
    messages.append({"role": "user", "content": message})
    response = openai.chat.completions.create(
        model = "gpt-5",
        messages=messages)
    reply = response.choices[0].message.content
    messages.append({"role": "assistant", "content": reply})
    print("\n" + reply + "\n")