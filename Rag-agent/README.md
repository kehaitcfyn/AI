# RAG Agent - Dokumentationsoversigt


## Brug af løsningen er eget ansvar !!

## Dokumenter

| Fil | Beskrivelse |
|-----|-------------|

| ** Kort intro til AI-Chat.docx    | kort intro

| **1-RAG-Agent-Dokumentation.pdf** | Hovedokumentationen - beskriver hele løsningen for både teknikere og slutbrugere. Indeholder frontend, backend, API endpoints og sikkerhedslag. |

| **2-Sikkerhedstillaeg.pdf** | Sikkerhedsanalyse med oversigt over implementeret sikkerhed (HttpOnly cookies, CSRF, JWT, rate limiting m.m.) samt forslag til forbedringer med kodeeksempler. |

| **3-Ingest-Script-Vejledning.pdf** | Brugervejledning til dokument-synkronisering. Forklarer hvordan scriptet håndterer nye, ændrede og slettede dokumenter i RAG-databasen. |

| **RAG-Agent-Arkitektur.png** | Visuelt diagram over løsningens arkitektur - viser både runtime-flow og dokument-synkronisering. |

| **chat.png**                 | Visuelt overblik af design. 

|** Proces embeddings + sprogmodel (OpenAI API)  | beskrivelse af processen når man bruger open AI som embeding og LLM  til sit eget RAG

## Hurtig oversigt

```
📁 Dokumentation
├── Kort intro til AI-Chat       → Kort intro til AI-Chat
├── 1-RAG-Agent-Dokumentation    → Hvad er løsningen?
├── 2-Sikkerhedstillaeg          → Hvor sikker er den + forbedringer
├── 3-Ingest-Script-Vejledning   → Hvordan synkroniseres dokumenter?
├── Proces embeddings sprogmodel → Proces embeddings sprogmode
└── RAG-Agent-Arkitektur.png     → Visuelt overblik
└── Chat.png                     → Visuelt overblik over design

📁 kode
├── Nginx config
├── Rag agent klar til Docker, dog skal mindre ting rettes til inden brug

📁 script
├── scripts til at teste løsningen

```
