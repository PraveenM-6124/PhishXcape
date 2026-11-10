"""
generate_architecture_diagram.py - Generates Output/Architecture diagram.png

Draws the multi-layer security detection architecture of PhishXcape:
1. Tab URL Interception (Chrome Tabs / Service Worker)
2. Feature Extractor (4 URL Features)
3. Local ML Inference (Random Forest Offline Engine)
4. Threat Intelligence Layer (Google Safe Browsing & VirusTotal REST APIs)
5. Multi-Layer Decision Engine (Confidence Score & Threat Aggregator)
6. Security Status Output (Safe, Suspicious, Phishing, Unknown) & Alert Injector
"""

import os
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import matplotlib.patches as patches

OUTPUT_PATH = os.path.join(os.path.dirname(__file__), "..", "Output", "Architecture diagram.png")

def create_architecture_diagram():
    fig, ax = plt.subplots(figsize=(14, 8), facecolor="#0B0B0F")
    ax.set_facecolor("#0B0B0F")
    ax.set_xlim(0, 14)
    ax.set_ylim(0, 8)
    ax.axis('off')
    
    # Title
    ax.text(7, 7.5, "PHISHXCAPE - MULTI-LAYER DETECTION ARCHITECTURE",
            ha='center', va='center', color='#FFFFFF', fontsize=18, fontweight='bold',
            fontfamily='sans-serif')
    ax.text(7, 7.05, "Real-Time Hybrid Security Pipeline: Offline Random Forest & Cloud Threat Intelligence",
            ha='center', va='center', color='#A1A1AA', fontsize=11)
            
    # Helper to draw styled box
    def draw_box(x, y, w, h, title, subtitle="", border_color="#E50914", bg_color="#1C1C24", title_color="#FFFFFF"):
        box = patches.FancyBboxPatch((x, y), w, h,
                                     boxstyle="round,pad=0.1,rounding_size=0.15",
                                     linewidth=1.8, edgecolor=border_color,
                                     facecolor=bg_color, zorder=2)
        ax.add_patch(box)
        if subtitle:
            ax.text(x + w/2, y + h*0.62, title, ha='center', va='center',
                    color=title_color, fontsize=10.5, fontweight='bold', zorder=3)
            ax.text(x + w/2, y + h*0.30, subtitle, ha='center', va='center',
                    color="#A1A1AA", fontsize=8.5, zorder=3)
        else:
            ax.text(x + w/2, y + h/2, title, ha='center', va='center',
                    color=title_color, fontsize=10.5, fontweight='bold', zorder=3)
                    
    # Helper to draw connector arrows
    def draw_arrow(x1, y1, x2, y2, color="#E50914", label="", offset_y=0.18):
        ax.annotate('', xy=(x2, y2), xytext=(x1, y1),
                    arrowprops=dict(arrowstyle="->,head_width=0.4,head_length=0.6",
                                    color=color, lw=2.0), zorder=4)
        if label:
            ax.text((x1 + x2)/2, (y1 + y2)/2 + offset_y, label, ha='center', va='center',
                    color="#FFFFFF", fontsize=8.5, fontweight='bold', zorder=5)

    # Stage 1: Input / Tab
    draw_box(0.5, 4.8, 2.4, 1.4, "Browser Navigation", "Active Chrome Tab\nURL Intercepted", border_color="#33333D")
    
    # Stage 2: Feature Extraction
    draw_box(3.5, 4.8, 2.5, 1.4, "Feature Extraction", "1. HTTPS Presence\n2. URL Length\n3. Subdomain Count\n4. Special Chars", border_color="#E50914")
    
    # Stage 3: ML Inference (Offline)
    draw_box(6.7, 4.8, 2.7, 1.4, "Offline ML Inference", "Random Forest Classifier\n100 Trees (JavaScript Engine)\nLocal & Zero-Latency", border_color="#E50914", bg_color="#241416")
    
    # Stage 4: Cloud Threat Intel (Parallel)
    draw_box(3.5, 1.6, 2.5, 1.4, "Google Safe Browsing", "v4 ThreatMatches API\nMalware, Social Eng,\nUnwanted Software", border_color="#B20710")
    draw_box(6.7, 1.6, 2.7, 1.4, "VirusTotal REST API", "v3 URL Analysis\nMultisource Antivirus Aggregation\nMalicious/Suspicious Count", border_color="#B20710")
    
    # Stage 5: Multi-layer Decision Engine
    draw_box(10.2, 3.2, 3.2, 2.2, "Multi-Layer Decision Policy", "Consolidates Evidence:\n• API Threats -> High-Risk Alert\n• ML Score -> Suspicious Alert\n• Offline Fallback Support\n• Transparent Classification", border_color="#FFFFFF", bg_color="#181822")
    
    # Stage 6: Output / UI Action
    draw_box(10.2, 0.5, 3.2, 1.5, "User Security Interface", "• Extension Popup (Red/Black/White)\n• In-Page Real-Time Alert Banner\n• Action Guidance & Diagnostics", border_color="#E50914")
    
    # Connectors
    draw_arrow(2.9, 5.5, 3.5, 5.5, label="Raw URL")
    draw_arrow(6.0, 5.5, 6.7, 5.5, label="4 Features")
    draw_arrow(9.4, 5.5, 10.2, 4.6, label="ML Prediction")
    
    # Split URL to APIs
    ax.plot([2.9, 3.2, 3.2], [5.5, 5.5, 2.3], color="#A1A1AA", lw=1.5, linestyle="--", zorder=1)
    draw_arrow(3.2, 2.3, 3.5, 2.3, color="#A1A1AA", label="Check")
    
    ax.plot([3.2, 6.4, 6.4], [2.3, 2.3, 2.3], color="#A1A1AA", lw=1.5, linestyle="--", zorder=1)
    draw_arrow(6.4, 2.3, 6.7, 2.3, color="#A1A1AA", label="Check")
    
    # APIs to Decision Engine
    draw_arrow(6.0, 2.0, 6.7, 2.0, color="#B20710")
    draw_arrow(9.4, 2.3, 10.2, 3.8, color="#B20710", label="Intel Verdicts")
    
    # Decision Engine to Output UI
    draw_arrow(11.8, 3.2, 11.8, 2.0, label="Status Verdict")

    plt.tight_layout()
    plt.savefig(OUTPUT_PATH, dpi=300, facecolor=fig.get_facecolor(), edgecolor='none')
    plt.close()
    print(f"[+] Architecture Diagram generated at: {OUTPUT_PATH}")

if __name__ == "__main__":
    create_architecture_diagram()
