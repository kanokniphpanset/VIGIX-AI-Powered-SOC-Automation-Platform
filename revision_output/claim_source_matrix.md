# Claim–Source Matrix: งานที่เกี่ยวข้อง (§2, ตารางที่ 2)

ตรวจ 2026-10-04 · ปิดประเด็น R-21 และ Q-12 (ค) · ใช้ตอบ PAQE F11

| ข้อความในบทความ | งาน | แหล่งที่ตรวจ | หลักฐานจากต้นฉบับ (สรุป/อ้างสั้น) | สถานะ |
|---|---|---|---|---|
| สร้างคู่มือการตอบสนองจากเหตุการณ์ Wazuh + RAG + LLM; ให้คำแนะนำเท่านั้น | [1] Ismail et al. | ฉบับเต็ม MDPI (mdpi.com/1424-8220/25/3/870) | ระบบให้ "tailored instruction guide" และ "context-aware recommendations"; ไม่ดำเนินการตอบสนองเอง | ยืนยัน |
| ค้นคืนจากคู่มือ IR, NIST CSF 2.0, MITRE ATT&CK; ไม่ได้รายงานตัวตรวจกับนโยบาย/แคตตาล็อก | [1] | ฉบับเต็ม MDPI | แหล่งความรู้ 3 แหล่ง; ไม่พบกลไกตรวจผลลัพธ์กับนโยบายหรือแคตตาล็อกก่อนแสดงผล | ยืนยัน |
| นักวิเคราะห์ทบทวนผ่านส่วนสนทนา ไม่มีขั้นอนุมัติ | [1] | ฉบับเต็ม MDPI | "a dynamic chat section … allowing users to interact with the system by providing additional instructions" | ยืนยัน |
| ไม่ได้รายงานการตรวจผลหลังการตอบสนอง | [1] | ฉบับเต็ม MDPI | ไม่พบการค้นหาซ้ำบน Wazuh หรือการตรวจการควบคุมภัย; งานต่อไปของผู้เขียนคือเชื่อมกับระบบ SOAR | ยืนยัน |
| ประเมินด้วย cosine similarity และ BERTScore | [1] | ฉบับเต็ม MDPI | 12 สถานการณ์โจมตี เทียบกับคำตอบอ้างอิง | ยืนยัน |
| CTI + RAG สร้างกลยุทธ์ลดผลกระทบ ไม่ดำเนินการเอง | [3] Tellache et al. | ฉบับเต็ม arXiv:2508.10677v1 (HTML) | "incident mitigation strategies"; ไม่พบการดำเนินการอัตโนมัติ | ยืนยัน |
| ไม่ได้รายงานการตรวจกับนโยบาย; ประเมินด้วยคะแนนจาก LLM | [3] | ฉบับเต็ม arXiv | Answer Relevance, Context Relevance, Groundedness ให้คะแนนโดย LLM; ไม่พบการตรวจกับนโยบาย/playbook | ยืนยัน |
| ผู้เชี่ยวชาญตรวจเพื่อการประเมิน ไม่ใช่ขั้นอนุมัติ | [3] | ฉบับเต็ม arXiv | "manual evaluations performed by security experts" ใช้ในการประเมินผล | ยืนยัน |
| ไม่ได้รายงานการตรวจผลหลังการตอบสนอง | [3] | ฉบับเต็ม arXiv | ไม่พบการค้นหาซ้ำบน SIEM หรือการตรวจการควบคุมภัย | ยืนยัน |
| เกมจำลอง Backdoors & Breaches; เอเจนต์แทนผู้เล่น; ตัดสินด้วยกติกาเกม; วัดด้วยอัตราการชนะ | [4] Liu and Anwar | ฉบับเต็ม arXiv:2508.13118 (PDF) | "Human players are replaced by … LLM-based agents"; ผลขึ้นกับการทอยลูกเต๋าตามกติกา; ตัวชี้วัดคือ win rate | ยืนยัน |
| ตรวจแผนกับขั้นตอนบังคับ ลำดับ จุดอนุมัติ ก่อนส่งนักวิเคราะห์; ไม่ได้รายงาน re-hunt | [2] Barbieri et al. | บทคัดย่อ arXiv:2605.05501 | "mandatory steps, required ordering, or approval gates before analyst review" | ยืนยันจากบทคัดย่อ |
| นักวิเคราะห์ยังเป็นผู้ตรวจสอบและตัดสินใจ | [5] Singh et al. | บทคัดย่อ arXiv:2508.18947 | การศึกษาการใช้ LLM ของนักวิเคราะห์ SOC | ยืนยันจากบทคัดย่อ |
| สร้างคำอธิบายเหตุการณ์ที่อ้างอิงหลักฐานด้วย LLM หลายเอเจนต์ | [6] Sheikhi et al. | หน้าคลังข้อมูล Univ. Oulu (ชื่อเรื่อง, เวที, หน้า, DOI) | ชื่อเรื่อง "Evidence-Backed Narrative Generation … Multi-Agent LLM Architecture"; BigData 2025 หน้า 7027–7036, DOI 10.1109/BigData66926.2025.11401968 | ยืนยันเฉพาะข้อมูลบรรณานุกรม — ฉบับเต็มเข้าถึงไม่ได้ (403) จึงไม่ใส่ [6] ในตารางที่ 2 |
| LLM จำแนกการแจ้งเตือนได้ดีกว่าการจัดลำดับความสำคัญ | [7] Rieger et al. | หน้า ScienceDirect | "alert prioritisation proved substantially more challenging across all evaluated LLMs" | ยืนยัน |

**ยังเปิดอยู่:** เวทีตีพิมพ์ของ [3] (GLOBECOM 2025) และ [4] (ICDMW 2025 หน้า 1190–1199) — หน้า arXiv ไม่ระบุ (Q-12 ก, ข)
