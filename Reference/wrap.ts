import type { XOTemplate } from '@xo-cash/types';

/**
 * Encodes the user parts of the https://wrapped.cash/ usecase as an XO template.
 *
 * The bootstrap ceremony is not encoded in this template, but the final categoryId
 * is properly encoded here and ensure we are operating with the correct token.
 */
export const wrapBCHTemplate: XOTemplate = {
	$schema: 'https://libauth.org/schemas/wallet-template-v0.schema.json',

	name: 'Wrapped BCH',
	description: 'Convert between BCH and wBCH tokens.',
	icon: 'wrap',

	version: '1',
	supported: ['BCH_2023_05', 'BCH_2024_05', 'BCH_2025_05', 'BCH_2026_05'],

	resources: [
		{
			name: 'Official Website',
			description: 'Official homepage for the wBCH token.',

			url: 'https://wrapped.cash/',
		}
	],

	roles: {
		wrapper: {
			name: 'Wrapper',
			description: 'The person wrapping BCH into wBCH.',
			icon: 'user',
		},
		unwrapper: {
			name: 'Unwrapper',
			description: 'The person unwrapping wBCH into BCH.',
			icon: 'user',
		},
		service: {
			name: 'Provider',
			description: 'The application providing the wrapping service.',
			icon: 'contract',
		},
	},

	// The engine has no knowledge of the covenant UTXOs and therefor cannot initiate wrap/unwrap, so the starting actions have been omitted.
	start: [],

	actions: {
		wrap: {
			name: 'Wrap BCH',
			description: 'Convert BCH into wBCH tokens.',
			icon: 'wrap',

			roles: {
				service: {
					requirements: {
						variables: ['direction', 'poolSatoshis', 'poolTokens'],
					},
				},
				wrapper: {
					requirements: {
						variables: ['amountToWrap', 'recipientLockingScript'],
					},
				},
			},

			requirements: {
				participants: [
					{ role: 'service', slots: { min: 1, max: 1 } },
					{ role: 'wrapper', slots: { min: 1, max: 1 } }
				],
			},

			transaction: 'wrapTransaction',
		},

		unwrap: {
			name: 'Unwrap wBCH',
			description: 'Convert wBCH tokens back into BCH.',
			icon: 'unwrap',

			roles: {
				service: {
					requirements: {
						variables: ['direction', 'poolSatoshis', 'poolTokens'],
					},
				},
				unwrapper: {
					requirements: {
						variables: ['amountToUnwrap', 'recipientLockingScript'],
					},
				},
			},

			requirements: {
				participants: [
					{ role: 'service', slots: { min: 1, max: 1 } },
					{ role: 'unwrapper', slots: { min: 1, max: 1 } }
				],
			},

			transaction: 'unwrapTransaction',
		},
	},

	transactions: {
		wrapTransaction: {
			name: 'Wrapped BCH',
			description: 'Wrapped $(<amountToWrap> <satoshisPerBCH> OP_DIV).$(<amountToWrap> <satoshisPerBCH> OP_MOD) BCH into wBCH tokens.',
			icon: 'wrap',

			inputs: [
				{ input: 'covenantInput', inputIndex: 0 },
			],
			outputs: [
				{ output: 'covenantOutput', outputIndex: 0 },
				{ output: 'wrappedTokensOutput', outputIndex: undefined },
			],
		},

		unwrapTransaction: {
			name: 'Unwrapped wBCH',
			description: 'Unwrapped $(<amountToUnwrap> <satoshisPerBCH> OP_DIV).$(<amountToUnwrap> <satoshisPerBCH> OP_MOD) wBCH tokens back into BCH.',
			icon: 'unwrap',

			inputs: [
				{ input: 'covenantInput', inputIndex: 0 },
			],
			outputs: [
				{ output: 'covenantOutput', outputIndex: 0 },
				{ output: 'unwrappedSatoshisOutput', outputIndex: undefined },
			],
		},
	},

	inputs: {
		covenantInput: {
			name: 'wBCH Covenant',
			description: 'The covenant being updated.',
			icon: 'contract',

			valueSatoshis: '$(poolSatoshis)',
			token: {
				category: '$(<wbchTokenCategory>)',
				amount: '$(poolTokens)',
				nft: null,
			},

			// TODO: This should be named unlockingBytecode, as it refers to raw script and not an unlocking script entry.
			unlockingScript: 'wrapBCHUnlockingBytecode',
		},
	},

	outputs: {
		covenantOutput: {
			name: 'wBCH Covenant',
			description: 'Holds BCH and wBCH tokens that can be freely converted.',
			icon: 'contract',

			valueSatoshis: '$(covenantChangeSatoshis)',
			token: {
				category: '$(<wbchTokenCategory>)',
				amount: '$(covenantChangeTokens)',
				nft: null,
			},

			lockingScript: 'wrapBCHLockingScript',
		},

		wrappedTokensOutput: {
			name: 'Wrapped wBCH',
			description: 'Wrapped $(<amountToWrap> <satoshisPerBCH> OP_DIV).$(<amountToWrap> <satoshisPerBCH> OP_MOD) wBCH tokens.',
			icon: 'receive',

			valueSatoshis: '<tokenDust>',
			token: {
				category: '$(<wbchTokenCategory>)',
				amount: '$(<amountToWrap>)',
				nft: null,
			},

			lockingScript: '$(<recipientLockingScript>)',
		},

		unwrappedSatoshisOutput: {
			name: 'Unwrapped BCH',
			description: 'Unwrapped $(<amountToUnwrap> <satoshisPerBCH> OP_DIV).$(<amountToUnwrap> <satoshisPerBCH> OP_MOD) BCH.',
			icon: 'receive',

			valueSatoshis: '$(<amountToUnwrap>)',
			token: null,

			lockingScript: '$(<recipientLockingScript>)',
		},
	},

	lockingScripts: {
		wrapBCHLockingScript: {
			name: 'wBCH Covenant',
			description: 'Holds BCH and wBCH tokens that can be freely converted.',
			icon: 'contract',

			lockingType: 'p2sh',
			lockingBytecode: 'wrapBCHLockingBytecode',

			roles: {
				service: {
					actions: [
						{
							action: 'wrap',
							role: 'service',
							variables: [
								{ direction: '$(<"wrap">)' },
								{ poolSatoshis: '$(XO_OUTPUTVALUE)' },
								{ poolTokens: '$(XO_OUTPUTTOKENAMOUNT)' },
							],
						},
						{
							action: 'unwrap',
							role: 'service',
							variables: [
								{ direction: '$(<"unwrap">)' },
								{ poolSatoshis: '$(XO_OUTPUTVALUE)' },
								{ poolTokens: '$(XO_OUTPUTTOKENAMOUNT)' },
							],
						},
					],
					balance: {
						satoshis: 0n,
						fungibleTokens: 0n,
					},
					selectable: false,
				},

				// Indicate that users should not index this locking script or their outputs.
				wrapper: { relevant: false },
				unwrapper: { relevant: false },
			},
		},
	},

	scripts: {
		// Utility to check if we are doing a wrap or unwrap.
		checkIfWrapping: '<direction> <"wrap"> OP_EQUAL',

		// Utilities to calculate the covenent change satoshis.
		wrappedChangeSatoshis: '<poolSatoshis> <amountToWrap> OP_ADD',
		unwrappedChangeSatoshis: '<poolSatoshis> <amountToUnwrap> OP_SUB',
		covenantChangeSatoshis: 'checkIfWrapping OP_IF wrappedChangeSatoshis OP_ELSE unwrappedChangeSatoshis OP_ENDIF',

		// Utilities to calculate the covenent change tokens.
		wrappedChangeTokens: '<poolTokens> <amountToWrap> OP_SUB',
		unwrappedChangeTokens: '<poolTokens> <amountToUnwrap> OP_ADD',
		covenantChangeTokens: 'checkIfWrapping OP_IF wrappedChangeTokens OP_ELSE unwrappedChangeTokens OP_ENDIF',

		// NOTE: This is the wrapped.cash covenant and so this bytecode cannot be updated.
		// NOTE: This covenant only ensure the security of its own funds, leaving user protection to be done in user space.
		enforceCovenantPersists: 'OP_INPUTINDEX OP_OUTPUTBYTECODE OP_INPUTINDEX OP_UTXOBYTECODE OP_EQUALVERIFY',
		enforceTokenCategoryPreserved: 'OP_INPUTINDEX OP_OUTPUTTOKENCATEGORY OP_INPUTINDEX OP_UTXOTOKENCATEGORY OP_EQUALVERIFY',
		enforceValueTokenSumConserved: 'OP_INPUTINDEX OP_UTXOTOKENAMOUNT OP_INPUTINDEX OP_UTXOVALUE OP_ADD OP_INPUTINDEX OP_OUTPUTTOKENAMOUNT OP_INPUTINDEX OP_OUTPUTVALUE OP_ADD OP_NUMEQUAL',

		// The final lock and unlocking bytecodes.
		wrapBCHLockingBytecode: 'enforceCovenantPersists enforceTokenCategoryPreserved enforceValueTokenSumConserved',
		wrapBCHUnlockingBytecode: '<wrapBCHLockingBytecode>',
	},

	constants: {
		wbchTokenCategory: {
			name: 'wBCH Token Category',
			description: 'The official token category for Wrapped BCH.',
			type: 'bytes',
			value: 'ff4d6e4b90aa8158d39c5dc874fd9411af1ac3b5ed6f354755e8362a0d02c6b3',
		},
		satoshisPerBCH: {
			name: 'Satoshis per BCH',
			description: 'Used to display amounts in BCH with decimals.',
			type: 'integer',
			value: 100000000,
		},
		tokenDust: {
			name: 'Token Dust Limit',
			description: 'Minimal satoshis required for a token-bearing output.',
			type: 'integer',
			value: 1000,
		},
	},

	variables: {

		// Internal variables to be provided by the application when choosing a pool UTXO.
		direction: {
			name: 'Wrap or Unwrap',
			description: 'Internal variable used to determine if we are wrapping or unwrapping.',
			type: 'string',
		},
		poolSatoshis: {
			name: 'Initial Pool Satoshis',
			description: 'Internal variable used to determine how much satoshis to keep on the covenant.',
			type: 'integer',
		},
		poolTokens: {
			name: 'Initial Pool Tokens',
			description: 'Internal variable used to determine how much fungible tokens to keep on the covenant.',
			type: 'integer',
		},

		// Public variables to be provided by the user.
		amountToWrap: {
			name: 'Amount to Wrap',
			description: 'How much BCH to convert to wBCH (in satoshis).',
			type: 'integer',
			hint: 'satoshis',
		},
		amountToUnwrap: {
			name: 'Amount to Unwrap',
			description: 'How much wBCH to convert back to BCH (in satoshis).',
			type: 'integer',
			hint: 'satoshis',
		},
		recipientLockingScript: {
			name: 'Destination',
			description: 'Where to receive your BCH or wBCH tokens.',
			type: 'bytes',
			hint: 'lockingScript',
		},
	},

	icons: [
		{ name: 'wrap', hash: '0000000000000000000000' },
		{ name: 'unwrap', hash: '0000000000000000000000' },
		{ name: 'user', hash: '0000000000000000000000' },
		{ name: 'contract', hash: '0000000000000000000000' },
		{ name: 'receive', hash: '0000000000000000000000' },
	],
};
