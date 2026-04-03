// packages/hdp-physical/src/edt/builder.ts
import type {
  EdtToken,
  EmbodimentSpec,
  ActionScope,
  IrreversibilitySpec,
  PolicyAttestation,
  DelegationScope,
} from '../types/edt.js'

export class EdtBuilder {
  private _embodiment?: EmbodimentSpec
  private _actionScope?: ActionScope
  private _irreversibility?: IrreversibilitySpec
  private _policyAttestation?: PolicyAttestation
  private _delegationScope?: DelegationScope

  setEmbodiment(e: EmbodimentSpec): this {
    this._embodiment = e
    return this
  }

  setActionScope(s: ActionScope): this {
    this._actionScope = s
    return this
  }

  setIrreversibility(i: IrreversibilitySpec): this {
    this._irreversibility = i
    return this
  }

  setPolicyAttestation(p: PolicyAttestation): this {
    this._policyAttestation = p
    return this
  }

  setDelegationScope(d: DelegationScope): this {
    this._delegationScope = d
    return this
  }

  build(): EdtToken {
    if (!this._embodiment) throw new Error('EdtBuilder: embodiment is required')
    if (!this._actionScope) throw new Error('EdtBuilder: action_scope is required')
    if (!this._irreversibility) throw new Error('EdtBuilder: irreversibility is required')
    if (!this._policyAttestation) throw new Error('EdtBuilder: policy_attestation is required')
    if (!this._delegationScope) throw new Error('EdtBuilder: delegation_scope is required')
    return {
      embodiment: this._embodiment,
      action_scope: this._actionScope,
      irreversibility: this._irreversibility,
      policy_attestation: this._policyAttestation,
      delegation_scope: this._delegationScope,
    }
  }
}
