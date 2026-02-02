\# Proces: Embeddings + sprogmodel (OpenAI API)



\## 1) Embeddings (til søgning/RAG)

\*\*Proces\*\*

1\. Dokumentet deles i mindre stykker (”chunks”)

2\. Hvert chunk sendes til OpenAI embeddings-modellen

3\. OpenAI returnerer embeddings (tal/vektorer)

4\. I gemmer embeddings + reference til teksten i jeres database (fx Postgres/pgvector)



\*\*Data der overføres til OpenAI\*\*

\- Tekstindholdet i hvert dokument-chunk (det I embedder)

\- Teknisk metadata i requesten (fx modelnavn, længder/format, request-id og netværksdata som IP)



\*\*Data der kommer tilbage\*\*

\- Embedding-vektorer (tal) + evt. forbrugs/response-metadata



---



\## 2) Sprogmodel (chat/svar-generering)

\*\*Proces\*\*

1\. Brugeren skriver et spørgsmål i jeres løsning

2\. (Valgfrit RAG) I henter relevante dokument-chunks fra jeres DB

3\. I bygger en prompt til modellen:

&nbsp;  - \*\*Systemprompt\*\* (”regler/rolle”)

&nbsp;  - Brugerens spørgsmål

&nbsp;  - Evt. dokumentuddrag (kontekst)

4\. Det sendes til OpenAI sprogmodellen

5\. OpenAI returnerer svaret (og evt. tool-calls, hvis I bruger det)



\*\*Data der overføres til OpenAI\*\*

\- \*\*Systemprompt\*\* (altid, hvis I bruger den)

\- Brugerens besked/spørgsmål

\- Evt. kontekst fra RAG (udvalgte dokumentuddrag/chunks)

\- Evt. samtalehistorik (hvis I sender den med)

\- Teknisk metadata i requesten (fx model, parametre som temperature/max\_output, request-id og netværksdata som IP)



\*\*Data der kommer tilbage\*\*

\- Model-svar (tekst/JSON) + evt. forbrugs/response-metadata



