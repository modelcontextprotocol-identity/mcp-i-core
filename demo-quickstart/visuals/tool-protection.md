# Visual 6: Tool Protection Flow

Copy this Mermaid block into your docs page under "Protect Specific Tools".

```mermaid
flowchart TD
    A["🤖 Agent calls tool"] --> B{"What kind of tool?"}

    B -->|"Public tool"| C["🔍 search"]
    C --> D["✅ Execute immediately"]
    D --> E["📝 Proof attached automatically"]

    B -->|"Protected tool"| F["🛒 place_order"]
    F --> G{"Has delegation VC?"}

    G -->|"No"| H["⚠️ needs_authorization"]
    H --> I["👤 Human approves"]
    I --> J["📜 Delegation VC issued"]
    J --> K["🔄 Agent retries with VC"]
    K --> L["✅ Verify VC → Execute"]

    G -->|"Yes"| L
    L --> M["📝 Response + signed proof"]

    style C fill:#10b981,color:#fff
    style F fill:#f59e0b,color:#fff
    style H fill:#ef4444,color:#fff
    style E fill:#10b981,color:#fff
    style M fill:#10b981,color:#fff
```
