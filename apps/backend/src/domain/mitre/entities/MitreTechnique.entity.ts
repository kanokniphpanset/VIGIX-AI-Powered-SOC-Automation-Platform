/** Read-only MITRE ATT&CK reference technique (mitre_techniques table). */
export interface MitreTechnique {
  techniqueId: string;
  name: string;
  tactics: string[];
  description: string | null;
}
