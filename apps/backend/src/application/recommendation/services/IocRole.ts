import { RecommendationContextDto } from "../dto/RecommendationContextDto";
import { iocKind } from "../../../domain/knowledge/knowledgeTypes";

type Context = Pick<RecommendationContextDto, "iocs" | "affectedHosts">;
export const NETWORK_ACTION_ROLE: Record<string, "source" | "destination"> = {
  "ACT-BLOCK-SOURCE-IP": "source", "ACT-RATE-LIMIT-SOURCE": "source", "ACT-BLOCK-DESTINATION-IP": "destination",
};

/** Only explicit trusted source fields establish direction; unknown/conflicting IP roles fail closed. */
export function compatibleIocRole(context: Context, action: string, target: string): boolean {
  const required = NETWORK_ACTION_ROLE[action];
  if (!required) return true; // Other kinds are enforced by the existing Action target-kind check.
  const records = context.iocs.filter(i => i.iocValue === target && iocKind(i.iocType) === "ip");
  return records.length > 0 && records.every(i => {
    const typed = /^(srcip|src_ip|source_ip)$/i.test(i.iocType) ? "source" : /^(dstip|dst_ip|destination_ip)$/i.test(i.iocType) ? "destination" : undefined;
    return (i.networkRole ?? typed) === required && (!typed || !i.networkRole || typed === i.networkRole);
  });
}

/** Explicit Wazuh/Sysmon/ECS fields, never prose, AI analysis, agent IP or an IP's mere presence. */
export function networkRoleFromPayload(payload: unknown, value: string): "source" | "destination" | undefined {
  const get = (path: string): unknown => path.split(".").reduce<unknown>((v, key) => v && typeof v === "object" ? (v as Record<string, unknown>)[key] : undefined, payload);
  const source = ["data.srcip", "data.src_ip", "data.sourceIp", "data.source.ip", "source.ip", "data.win.eventdata.sourceIp", "data.win.eventdata.SourceIp"].some(p => get(p) === value);
  const destination = ["data.dstip", "data.dst_ip", "data.destinationIp", "data.destination.ip", "destination.ip", "data.win.eventdata.destinationIp", "data.win.eventdata.DestinationIp"].some(p => get(p) === value);
  return source === destination ? undefined : source ? "source" : "destination";
}
