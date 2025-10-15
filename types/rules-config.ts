import { z } from "zod";

export const SeveritySchema = z.enum([
  "critical",
  "high",
  "medium",
  "low",
  "informational",
]);
export type Severity = z.infer<typeof SeveritySchema>;

export const ConditionComparatorSchema = z.enum([
  "equals",
  "not_equals",
  "in",
  "not_in",
  "contains",
  "not_contains",
  "greater_than",
  "greater_or_equal",
  "less_than",
  "less_or_equal",
  "matches_port_group",
  "matches_admin_port",
  "exists",
  "not_exists",
]);
export type ConditionComparator = z.infer<typeof ConditionComparatorSchema>;

export const RuleConditionThresholdSchema = z
  .object({
    minValue: z.number().optional(),
    maxValue: z.number().optional(),
    inclusive: z.boolean().optional().default(true),
  })
  .refine(
    (value) => {
      if (value.minValue !== undefined && value.maxValue !== undefined) {
        return value.minValue <= value.maxValue;
      }
      return true;
    },
    {
      message: "minValue cannot exceed maxValue",
      path: ["minValue"],
    },
  );

export type RuleConditionThreshold = z.infer<typeof RuleConditionThresholdSchema>;

export const RuleConditionSchema = z
  .object({
    field: z.string().min(1),
    comparator: ConditionComparatorSchema,
    value: z.unknown().optional(),
    values: z.array(z.unknown()).optional(),
    threshold: RuleConditionThresholdSchema.optional(),
  })
  .superRefine((condition, ctx) => {
    if (
      (condition.comparator === "exists" || condition.comparator === "not_exists") &&
      condition.threshold === undefined
    ) {
      return;
    }
    if (
      condition.value === undefined &&
      (condition.values === undefined || condition.values.length === 0) &&
      condition.threshold === undefined
    ) {
      ctx.addIssue({
        path: ["value"],
        code: z.ZodIssueCode.custom,
        message: "A comparator requires a value, values, or threshold",
      });
    }
  });

export type RuleCondition = z.infer<typeof RuleConditionSchema>;

export interface ConditionGroup {
  logic: "all" | "any";
  conditions: RuleCondition[];
  groups: ConditionGroup[];
}

export const ConditionGroupSchema: z.ZodType<ConditionGroup> = z.lazy(() =>
  z.object({
    logic: z.enum(["all", "any"]).default("all"),
    conditions: z.array(RuleConditionSchema).default([]),
    groups: z.array(ConditionGroupSchema).default([]),
  }),
);

export interface BaseRuleDefinition {
  id: string;
  label: string;
  description: string;
}

export const AnalyzerPortConfigurationSchema = z.object({
  baseline: z.array(z.number().int().min(1)).default([]),
  perRiskOverrides: z.record(z.array(z.number().int().min(1))).default({}),
});

export interface AnalyzerPortConfiguration {
  baseline: number[];
  perRiskOverrides: Record<string, number[]>;
}

export const AnalyzerMetadataSchema = z.object({
  enabled: z.boolean().default(true),
  notes: z.string().default(""),
  severityOverrides: z.record(SeveritySchema).default({}),
  adminPorts: AnalyzerPortConfigurationSchema.default({
    baseline: [],
    perRiskOverrides: {},
  }),
});

export interface AnalyzerMetadata {
  enabled: boolean;
  notes: string;
  severityOverrides: Record<string, Severity>;
  adminPorts: AnalyzerPortConfiguration;
}

export const RuleDefinitionSchema = z
  .object({
    id: z.string().min(1),
    label: z.string().min(1),
    description: z.string().default(""),
    conditions: ConditionGroupSchema,
    analyzers: z.record(AnalyzerMetadataSchema),
  })
  .transform((value) => ({
    ...value,
    description: value.description ?? "",
  }));

export interface RuleDefinition extends BaseRuleDefinition {
  conditions: ConditionGroup;
  analyzers: Record<string, AnalyzerMetadata>;
}

export const RulesContractSchema = z.record(RuleDefinitionSchema);
export type RulesContract = z.infer<typeof RulesContractSchema>;
