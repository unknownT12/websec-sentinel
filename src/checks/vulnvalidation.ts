import type { Check } from "../types.js";
import { runConfirmedValidations, validationsToResults } from "../core/vulnerabilityVerifier.js";

export const vulnerabilityValidationCheck: Check = {
  name: "vulnvalidation",
  description: "Performs safe, reproducible application-layer validation instead of keyword-only benchmark signals.",
  async run(context) {
    const validations = await runConfirmedValidations(context);
    return validationsToResults(validations);
  },
};
