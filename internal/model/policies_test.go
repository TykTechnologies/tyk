package model_test

import (
	"testing"

	persistentmodel "github.com/TykTechnologies/storage/persistent/model"
	"github.com/TykTechnologies/tyk/internal/model"
	"github.com/TykTechnologies/tyk/user"
	"github.com/samber/lo"
	"github.com/stretchr/testify/require"
)

func Test_EnsurePolicyId(t *testing.T) {
	objectId := persistentmodel.NewObjectID()

	for _, tc := range []struct {
		name           string
		input          *user.Policy
		expectedResult bool
		expectedId     string
	}{
		{
			name:           "skips if id is provided and MID is invalid",
			input:          &user.Policy{ID: "my-custom-id"},
			expectedResult: true,
			expectedId:     "my-custom-id",
		},
		{
			name:           "skips if id is provided and MID is valid",
			input:          &user.Policy{MID: objectId, ID: "my-custom-id"},
			expectedResult: true,
			expectedId:     "my-custom-id",
		},
		{
			name:           "returns false if is is not provided and MID is invalid",
			input:          &user.Policy{ID: "", MID: "invalid"},
			expectedResult: false,
			expectedId:     "",
		},
		{
			name:           "returns true and sets id if ID is not defined and MID is valid",
			input:          &user.Policy{ID: "", MID: objectId},
			expectedResult: true,
			expectedId:     objectId.Hex(),
		},
		{
			name:           "returns false if provided policy is nil",
			input:          nil,
			expectedResult: false,
			expectedId:     "",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			res := model.EnsurePolicyId(tc.input)
			require.Equal(t, tc.expectedResult, res)

			if tc.input != nil {
				require.Equal(t, tc.expectedId, tc.input.ID)
			}
		})
	}
}

func Test_Policies(t *testing.T) {
	t.Run("Reload", func(t *testing.T) {
		t.Run("returns number of uniq policies", func(t *testing.T) {
			pols := model.NewPolicies()
			pols.Reload([]user.Policy{
				{MID: persistentmodel.NewObjectID(), ID: "my-custom-id"},
				{MID: persistentmodel.NewObjectID(), ID: "my-custom-id"},
			}...)

			require.Equal(t, 2, pols.PolicyCount())
			require.Equal(t, 2, len(pols.AsSlice()))
		})

		t.Run("resets existent policy entries", func(t *testing.T) {
			pols := model.NewPolicies()

			pols.Reload([]user.Policy{
				{MID: persistentmodel.NewObjectID(), ID: "my-custom-id1"},
				{MID: persistentmodel.NewObjectID(), ID: "my-custom-id2"},
			}...)

			pols.Reload([]user.Policy{
				{MID: persistentmodel.NewObjectID(), ID: "my-custom-id3"},
			}...)

			require.Equal(t, 1, pols.PolicyCount())
			require.Equal(t, 1, len(pols.AsSlice()))
			pol, err := pols.PolicyByIdExtended(model.NonScopedPolicyId("my-custom-id3"))
			require.NoError(t, err)
			require.Equal(t, "my-custom-id3", pol.ID)
		})

		t.Run("rejects invalid policies", func(t *testing.T) {
			pols := model.NewPolicies()
			pols.Reload([]user.Policy{
				// non-invalid
				{MID: persistentmodel.NewObjectID(), ID: "pol1", OrgID: "org1"},
				{MID: "", ID: "valid", OrgID: "org1"},
				// invalid because of empty id and invalid MID
				{MID: "", ID: "", OrgID: "org1"},
				{MID: "furkan", ID: "", OrgID: "org1"},
			}...)

			require.Equal(t, 2, pols.PolicyCount())

			for _, id := range []model.PolicyID{
				model.NonScopedPolicyId("valid"),
				model.NonScopedPolicyId("pol1"),
			} {
				_, err := pols.PolicyByIdExtended(id)
				require.NoError(t, err)
			}
		})

	})

	t.Run("FindMethods", func(t *testing.T) {

		pols := model.NewPolicies()
		pols.Reload([]user.Policy{
			{MID: persistentmodel.NewObjectID(), ID: "pol1", OrgID: "org1"},
			{MID: persistentmodel.NewObjectID(), ID: "pol1", OrgID: "org2"},
		}...)

		t.Run("NonScopedLastInsertedPolicyId", func(t *testing.T) {
			t.Run("returns last inserted policy", func(t *testing.T) {
				pol, err := pols.PolicyByIdExtended(model.NonScopedLastInsertedPolicyId("pol1"))
				require.NoError(t, err)
				require.Equal(t, "pol1", pol.ID)
				require.Equal(t, "org2", pol.OrgID)

				pol, ok := pols.PolicyByID(model.NonScopedLastInsertedPolicyId("pol1"))
				require.True(t, ok)
				require.Equal(t, "pol1", pol.ID)
				require.Equal(t, "org2", pol.OrgID)
			})

			t.Run("does not return policy if not exists", func(t *testing.T) {
				_, err := pols.PolicyByIdExtended(model.NonScopedLastInsertedPolicyId("non-existent"))
				require.ErrorIs(t, err, model.ErrPolicyNotFound)

				_, ok := pols.PolicyByID(model.NonScopedLastInsertedPolicyId("non-existent"))
				require.False(t, ok)
			})
		})

		t.Run("NonScopedPolicyId", func(t *testing.T) {
			t.Run("returns ambiguity error", func(t *testing.T) {
				_, err := pols.PolicyByIdExtended(model.NonScopedPolicyId("pol1"))
				require.ErrorIs(t, err, model.ErrAmbiguousState)

				_, ok := pols.PolicyByID(model.NonScopedPolicyId("pol1"))
				require.False(t, ok)
			})

			t.Run("does not return policy if not exists", func(t *testing.T) {
				_, err := pols.PolicyByIdExtended(model.NonScopedPolicyId("non-existent"))
				require.ErrorIs(t, err, model.ErrPolicyNotFound)

				_, ok := pols.PolicyByID(model.NonScopedPolicyId("non-existent"))
				require.False(t, ok)
			})
		})

		t.Run("ScopedCustomPolicyId", func(t *testing.T) {
			t.Run("returns proper policy", func(t *testing.T) {
				pol, err := pols.PolicyByIdExtended(model.NewScopedCustomPolicyId("org2", "pol1"))
				require.NoError(t, err)
				require.Equal(t, "pol1", pol.ID)
				require.Equal(t, "org2", pol.OrgID)

				pol, ok := pols.PolicyByID(model.NewScopedCustomPolicyId("org2", "pol1"))
				require.True(t, ok)
				require.Equal(t, "pol1", pol.ID)
				require.Equal(t, "org2", pol.OrgID)

				pol, err = pols.PolicyByIdExtended(model.NewScopedCustomPolicyId("org1", "pol1"))
				require.NoError(t, err)
				require.Equal(t, "pol1", pol.ID)
				require.Equal(t, "org1", pol.OrgID)

				pol, ok = pols.PolicyByID(model.NewScopedCustomPolicyId("org1", "pol1"))
				require.True(t, ok)
				require.Equal(t, "pol1", pol.ID)
				require.Equal(t, "org1", pol.OrgID)
			})

			t.Run("returns err not found if non existent policy id was provided", func(t *testing.T) {
				_, err := pols.PolicyByIdExtended(model.NewScopedCustomPolicyId("org2", "pol-non-existent"))
				require.ErrorIs(t, err, model.ErrPolicyNotFound)
				_, ok := pols.PolicyByID(model.NewScopedCustomPolicyId("org2", "pol-non-existent"))
				require.False(t, ok)
			})

			t.Run("returns err not found if wrong org was provided", func(t *testing.T) {
				_, err := pols.PolicyByIdExtended(model.NewScopedCustomPolicyId("non-existent-org", "pol1"))
				require.ErrorIs(t, err, model.ErrPolicyNotFound)
				_, ok := pols.PolicyByID(model.NewScopedCustomPolicyId("non-existent-org", "pol1"))
				require.False(t, ok)
			})
		})
	})

	t.Run("DeleteById", func(t *testing.T) {
		t.Run("removes given entries", func(t *testing.T) {
			pols := model.NewPolicies()
			pols.Reload([]user.Policy{
				{MID: persistentmodel.NewObjectID(), ID: "pol1", OrgID: "org1"},
				{MID: persistentmodel.NewObjectID(), ID: "pol1", OrgID: "org2"},
			}...)

			pols.DeleteById(model.NewScopedCustomPolicyId("org1", "pol1"))

			policies := pols.AsSlice()

			require.Equal(t, 1, pols.PolicyCount())
			require.Equal(t, 1, len(policies))
			pol1 := policies[0]

			require.Equal(t, "org2", pol1.OrgID)
			require.Equal(t, "pol1", pol1.ID)
		})
	})

	t.Run("Hooks", func(t *testing.T) {
		t.Run("WithCombined", func(t *testing.T) {
			t.Run("combines hooks in one callback", func(t *testing.T) {
				var calledFirst = false
				var calledSecond = false

				_ = model.NewPolicies(
					model.WithCombined(
						func(policies *model.Policies) {
							calledFirst = true
						},
						func(policies *model.Policies) {
							calledSecond = true
						},
					),
				)

				require.True(t, calledFirst)
				require.True(t, calledSecond)
			})
		})

		t.Run("WithLoadFail", func(t *testing.T) {
			t.Run("invokes on broken policy met", func(t *testing.T) {
				var brokenPolicies []user.Policy

				pols := model.NewPolicies(model.WithLoadFail(func(policy *user.Policy) {
					brokenPolicies = append(brokenPolicies, *policy)
				}))

				pols.Reload([]user.Policy{
					{MID: persistentmodel.NewObjectID(), ID: "pol1", OrgID: "org1"},
					{MID: "", ID: "", OrgID: "org1"},
					{MID: "furkan", ID: "", OrgID: "org1"},
				}...)

				require.Equal(t, 2, len(brokenPolicies))
			})
		})

		t.Run("WithCollisionMultiTenant", func(t *testing.T) {
			type collision struct {
				customId string
				dbIds    []persistentmodel.ObjectID
			}

			var collisions []collision
			pols := model.NewPolicies(model.WithCollisionMultiTenant(func(customId string, dbIds []persistentmodel.ObjectID) {
				collisions = append(collisions, collision{
					customId: customId,
					dbIds:    dbIds,
				})
			}))

			pols.Reload([]user.Policy{
				// collision1
				{MID: persistentmodel.NewObjectID(), ID: "collision1", OrgID: "org1"},
				{MID: persistentmodel.NewObjectID(), ID: "collision1", OrgID: "org2"},
				{MID: persistentmodel.NewObjectID(), ID: "collision1", OrgID: "org3"},
				// collision2
				{MID: persistentmodel.NewObjectID(), ID: "collision2", OrgID: "org1"},
				{MID: persistentmodel.NewObjectID(), ID: "collision2", OrgID: "org2"},
				// non-collision
				{MID: persistentmodel.NewObjectID(), ID: "pol1", OrgID: "org1"},
				{MID: persistentmodel.NewObjectID(), ID: "pol2", OrgID: "org2"},
				{MID: persistentmodel.NewObjectID(), ID: "pol3", OrgID: "org3"},
			}...)

			collisionsMap := lo.SliceToMap(collisions, func(item collision) (string, []persistentmodel.ObjectID) {
				return item.customId, item.dbIds
			})

			require.Equal(t, 2, len(collisions))

			require.Contains(t, collisionsMap, "collision1")
			require.Len(t, collisionsMap["collision1"], 3)

			require.Contains(t, collisionsMap, "collision2")
			require.Len(t, collisionsMap["collision2"], 2)
		})
	})
}
