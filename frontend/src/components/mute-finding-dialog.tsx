import { useState } from "react";
import { LoaderCircle } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Label } from "@/components/ui/label";
import { Combobox } from "@/components/combobox";
import { Textarea } from "@/components/ui/textarea";
import { MUTE_REASON_LABELS, type MuteReason } from "@/components/overlay-rail";
import { useStatus } from "@/components/status-region";
import { errorMessage } from "@/api/client";
import type { Finding } from "@/api/types";
import { useUpdateFinding } from "@/hooks/queries";

export const MUTE_REASONS = Object.keys(MUTE_REASON_LABELS) as MuteReason[];

/** The single mute/edit-mute/unmute dialog for one finding — shared by the
 *  Findings table (row action) and the Finding detail page, so there is
 *  exactly one place this form's behavior lives. */
export function MuteFindingDialog({
  finding,
  onOpenChange,
}: {
  finding: Finding;
  onOpenChange: (open: boolean) => void;
}) {
  const updateFinding = useUpdateFinding();
  const status = useStatus();

  const [reason, setReason] = useState<string>(finding.mute_reason ?? "");
  const [note, setNote] = useState(finding.note ?? "");

  const handleSubmit = async (event: React.FormEvent) => {
    event.preventDefault();
    if (!reason) return;
    try {
      await updateFinding.mutateAsync({
        id: finding.id,
        muted: true,
        mute_reason: reason,
        note: note.trim() || null,
      });
      status.succeed(`Muted ${finding.check_id} on ${finding.resource_name}.`);
      onOpenChange(false);
    } catch (error) {
      status.fail(errorMessage(error, "Couldn't mute that finding."));
    }
  };

  const handleUnmute = async () => {
    try {
      await updateFinding.mutateAsync({
        id: finding.id, muted: false, mute_reason: null, note: note.trim() || null,
      });
      status.succeed(`Unmuted ${finding.check_id} on ${finding.resource_name}.`);
      onOpenChange(false);
    } catch (error) {
      status.fail(errorMessage(error, "Couldn't unmute that finding."));
    }
  };

  return (
    <Dialog open onOpenChange={onOpenChange}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>{finding.muted ? "Edit mute" : "Mute finding"}</DialogTitle>
        </DialogHeader>
        <form onSubmit={handleSubmit} className="space-y-4">
          <div className="space-y-1">
            <p className="text-sm font-medium text-ink">{finding.check_title}</p>
            <p className="font-mono text-xs text-ink-muted">{finding.resource_name}</p>
          </div>
          {/* The failing/passing status underneath is never affected by
              this — mute is an annotation on top of it, not a replacement
              for it. */}
          <div className="space-y-1.5">
            <Label htmlFor="mute-reason">Reason</Label>
            <Combobox
              id="mute-reason"
              value={reason}
              onValueChange={setReason}
              options={MUTE_REASONS.map((value) => ({
                value: value,
                label: MUTE_REASON_LABELS[value],
              }))}
              placeholder="Select a reason"
              className="w-full"
            />
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="mute-note">Note</Label>
            <Textarea
              id="mute-note"
              value={note}
              onChange={(event) => setNote(event.target.value)}
              placeholder="Context for the next person who looks at this — a ticket reference, why it's safe…"
            />
          </div>
          <DialogFooter>
            {finding.muted && (
              <Button
                type="button"
                variant="outline"
                onClick={handleUnmute}
                disabled={updateFinding.isPending}
              >
                Unmute
              </Button>
            )}
            <Button type="submit" disabled={updateFinding.isPending || !reason}>
              {updateFinding.isPending && (
                <LoaderCircle className="size-3.5 animate-spin" aria-hidden />
              )}
              {finding.muted ? "Save" : "Mute"}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}
