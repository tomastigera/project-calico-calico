// Copyright (c) 2021 Tigera, Inc. All rights reserved.

package userscache

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("OIDCUserCache", func() {
	Context("UpdateOIDCUsers", func() {
		It("adds oidc user to cache", func() {
			subId := "randomSubjectId1"
			oidcUsers := map[string]OIDCUser{
				"randomSubjectId1": {Username: "testuser", Groups: []string{"group1", "group2"}},
			}

			userCache := NewOIDCUserCache()
			users := userCache.UpdateOIDCUsers(oidcUsers)
			Expect(users).Should(ContainElements([]string{subId}))

			Expect(userCache.Exists(subId)).Should(BeTrue())
			Expect(userCache.SubjectIDs()).Should(ContainElements([]string{subId}))
			Expect(userCache.SubjectIDToUserOrGroups(subId)).Should(ContainElements([]string{"group1", "group2", "testuser"}))
			Expect(userCache.UserOrGroupToSubjectIDs("group1")).Should(ContainElements([]string{subId}))
			Expect(userCache.UserOrGroupToSubjectIDs("group2")).Should(ContainElements([]string{subId}))
			Expect(userCache.UserOrGroupToSubjectIDs("testuser")).Should(ContainElements([]string{subId}))

		})

		It("updates oidc user in cache", func() {
			oidcUsers := map[string]OIDCUser{
				"randomSubjectId1": {Username: "testuser1", Groups: []string{"group1", "group2"}},
				"randomSubjectId2": {Username: "testuser2", Groups: []string{}},
			}

			userCache := NewOIDCUserCache()
			users := userCache.UpdateOIDCUsers(oidcUsers)
			Expect(users).Should(ContainElements([]string{"randomSubjectId1", "randomSubjectId2"}))
			Expect(userCache.SubjectIDToUserOrGroups("randomSubjectId2")).Should(ContainElements([]string{"testuser2"}))

			oidcUsers = map[string]OIDCUser{
				"randomSubjectId2": {Username: "testuser2", Groups: []string{"group1", "group2"}},
			}
			users = userCache.UpdateOIDCUsers(oidcUsers)
			Expect(users).Should(BeEquivalentTo([]string{"randomSubjectId2"}))
			Expect(userCache.SubjectIDToUserOrGroups("randomSubjectId2")).Should(ContainElements([]string{"group1", "group2", "testuser2"}))
			Expect(userCache.UserOrGroupToSubjectIDs("testuser2")).Should(ContainElements([]string{"randomSubjectId2"}))

			oidcUsers = map[string]OIDCUser{
				"randomSubjectId1": {Username: "testuser1", Groups: []string{"group1", "group2"}},
				"randomSubjectId2": {Username: "testuser2", Groups: []string{"group1"}},
			}
			users = userCache.UpdateOIDCUsers(oidcUsers)
			Expect(users).Should(ContainElements([]string{"randomSubjectId1", "randomSubjectId2"}))
			Expect(userCache.SubjectIDToUserOrGroups("randomSubjectId1")).Should(ContainElements([]string{"group1", "group2", "testuser1"}))
			Expect(userCache.SubjectIDToUserOrGroups("randomSubjectId2")).Should(ContainElements([]string{"group1", "testuser2"}))
			Expect(userCache.UserOrGroupToSubjectIDs("group1")).Should(ContainElements([]string{"randomSubjectId1", "randomSubjectId2"}))
			Expect(userCache.UserOrGroupToSubjectIDs("group2")).Should(ContainElements([]string{"randomSubjectId1"}))
		})
	})

	Context("DeleteOIDCUser", func() {
		It("deletes oidc user from cache", func() {
			oidcUsers := map[string]OIDCUser{
				"randomSubjectId1": {Username: "testuser1", Groups: []string{"group1", "group2"}},
				"randomSubjectId2": {Username: "testuser2", Groups: []string{"group1"}},
			}

			userCache := NewOIDCUserCache()
			userCache.UpdateOIDCUsers(oidcUsers)
			Expect(userCache.UserOrGroupToSubjectIDs("group1")).Should(ContainElements([]string{"randomSubjectId1", "randomSubjectId2"}))
			Expect(userCache.UserOrGroupToSubjectIDs("group2")).Should(ContainElements([]string{"randomSubjectId1"}))

			Expect(userCache.DeleteOIDCUser("randomSubjectId2")).Should(BeTrue())
			Expect(userCache.SubjectIDToUserOrGroups("randomSubjectId1")).Should(ContainElements([]string{"group1", "group2"}))
			Expect(userCache.SubjectIDToUserOrGroups("randomSubjectId2")).Should(BeNil())
			Expect(userCache.UserOrGroupToSubjectIDs("group1")).Should(ContainElements([]string{"randomSubjectId1"}))
			Expect(userCache.UserOrGroupToSubjectIDs("group2")).Should(ContainElements([]string{"randomSubjectId1"}))
		})
	})
})
