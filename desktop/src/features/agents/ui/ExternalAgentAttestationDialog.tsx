import * as React from "react";

import { Button } from "@/shared/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/shared/ui/dialog";
import { Input } from "@/shared/ui/input";
import { CopyButton } from "./CopyButton";
import {
  attestExternalAgent,
  createExternalAgentAuthTag,
} from "./externalAgentAttestation";

export function ExternalAgentAttestationDialog({
  open,
  onOpenChange,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
}) {
  const [agentPubkey, setAgentPubkey] = React.useState("");
  const [authTag, setAuthTag] = React.useState<string | null>(null);
  const [error, setError] = React.useState<string | null>(null);
  const [isPending, setIsPending] = React.useState(false);

  React.useEffect(() => {
    if (!open) {
      setAgentPubkey("");
      setAuthTag(null);
      setError(null);
      setIsPending(false);
    }
  }, [open]);

  async function handleAttest(event: React.FormEvent) {
    event.preventDefault();
    setError(null);
    setAuthTag(null);
    setIsPending(true);
    try {
      setAuthTag(
        await createExternalAgentAuthTag(agentPubkey, attestExternalAgent),
      );
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : String(cause));
    } finally {
      setIsPending(false);
    }
  }

  return (
    <Dialog onOpenChange={onOpenChange} open={open}>
      <DialogContent className="max-w-2xl overflow-hidden p-0">
        <form className="flex max-h-[85vh] flex-col" onSubmit={handleAttest}>
          <DialogHeader className="border-b border-border/60 px-6 py-5 pr-14">
            <DialogTitle>Attest external agent</DialogTitle>
            <DialogDescription>
              Authorize an existing agent public key without importing its
              private key. Your owner key stays in Buzz Desktop.
            </DialogDescription>
          </DialogHeader>

          <div className="flex-1 space-y-4 overflow-y-auto px-6 py-5">
            <label className="block space-y-2" htmlFor="external-agent-pubkey">
              <span className="text-sm font-medium">Agent public key</span>
              <Input
                autoComplete="off"
                autoFocus
                id="external-agent-pubkey"
                onChange={(event) => setAgentPubkey(event.target.value)}
                placeholder="64-character hex public key"
                spellCheck={false}
                value={agentPubkey}
              />
            </label>

            {error ? (
              <p className="rounded-2xl border border-destructive/30 bg-destructive/10 px-4 py-3 text-sm text-destructive">
                {error}
              </p>
            ) : null}

            {authTag ? (
              <div className="rounded-2xl border border-border/70 bg-muted/20 p-4">
                <div className="flex items-center justify-between gap-3">
                  <div>
                    <p className="text-sm font-semibold tracking-tight">
                      BUZZ_AUTH_TAG
                    </p>
                    <p className="text-sm text-muted-foreground">
                      Install this value in the external agent runtime.
                    </p>
                  </div>
                  <CopyButton label="Copy auth tag" value={authTag} />
                </div>
                <code className="mt-3 block break-all rounded-xl border border-border/70 bg-background/80 px-3 py-2 text-xs">
                  {authTag}
                </code>
              </div>
            ) : null}
          </div>

          <div className="flex justify-end gap-2 border-t border-border/60 px-6 py-4">
            <Button
              onClick={() => onOpenChange(false)}
              size="sm"
              type="button"
              variant="outline"
            >
              {authTag ? "Done" : "Cancel"}
            </Button>
            <Button
              disabled={isPending || agentPubkey.trim().length === 0}
              size="sm"
              type="submit"
            >
              {isPending ? "Signing…" : "Create auth tag"}
            </Button>
          </div>
        </form>
      </DialogContent>
    </Dialog>
  );
}
